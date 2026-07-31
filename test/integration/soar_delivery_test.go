//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ALERT DELIVERY, ROUTING AND THE INTEGRATION RUNNERS (D304).
//
// An alert nobody is TOLD about is a row in a table. Everything upstream of this — detection,
// correlation, incidents — produces a queue, and this is the machinery that reaches a human. None of it
// had ever run in a shipped process under test: the webhook, the retry, the routing table, the ITSM
// ticket sync and the IdP responder were all covered by package tests and by nothing that starts a
// binary.
//
// That matters more than it sounds. `notify` is best-effort by design — a down sink never breaks ingest
// — so every failure mode here is SILENT. A misdelivered page and no page look identical from inside the
// control plane, and the only place the difference is visible is at the receiver.

// sink records what a webhook receiver actually got.
type sink struct {
	mu   sync.Mutex
	got  []map[string]any
	code int
	addr string
}

func startSink(t *testing.T, status int) *sink {
	t.Helper()
	s := &sink{code: status}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		s.mu.Lock()
		s.got = append(s.got, m)
		s.mu.Unlock()
		w.WriteHeader(s.code)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

// details returns every delivered notification's Detail string. Kept beside kinds() because a page's
// WORDING is a product property in its own right: two incidents that read identically get triaged
// identically, so "this came back twenty minutes after we closed it" only counts if it arrives.
func (s *sink) details() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.got))
	for _, m := range s.got {
		d, _ := m["detail"].(string)
		out = append(out, d)
	}
	return out
}

func (s *sink) kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.got))
	for _, m := range s.got {
		k, _ := m["kind"].(string)
		out = append(out, k)
	}
	return out
}

// TestAnIncidentIsDeliveredToAWebhook is the base case: a raised incident reaches a human.
func TestAnIncidentIsDeliveredToAWebhook(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	receiver := startSink(t, http.StatusOK)

	setDynamic(t, stack, "OPENSHIELD_ALERT_WEBHOOK", "http://"+receiver.addr+"/hook")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	seedBurst(t, stack, "subject-paged", 5, 0.95)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("alert delivery enabled", 90*time.Second)

	Eventually(t, 90*time.Second, "the incident to be delivered to the webhook", func() bool {
		return receiver.count() > 0
	})

	// The payload is PSEUDONYMOUS and carries no content. A webhook goes to a third-party system —
	// chat, a pager, a SIEM — so a notification carrying evidence would export it there.
	receiver.mu.Lock()
	first := receiver.got[0]
	receiver.mu.Unlock()
	body, _ := json.Marshal(first)
	for _, leak := range []string{"111.444.777-35", "payload", "content"} {
		if contains(string(body), leak) {
			t.Errorf("the delivered notification contains %q — a page leaves the platform, and anything in "+
				"it has been exported to whoever operates the receiver:\n%s", leak, body)
		}
	}
	if k, _ := first["kind"].(string); k == "" {
		t.Errorf("the notification names no kind, so a receiver cannot route it:\n%s", body)
	}

	// SOAR-1: raised ONCE. Re-correlating the same burst must not re-page — a pager that repeats gets
	// silenced, and a silenced pager is the same as no pager.
	at := receiver.count()
	time.Sleep(6 * time.Second)
	if after := receiver.count(); after > at {
		t.Errorf("the same incident paged again (%d → %d deliveries) — SOAR-1 pages on a genuine INSERT, "+
			"and a repeat page is how an on-call rotation learns to ignore this system", at, after)
	}
}

// TestAlertRoutingSendsToTheSelectedSinkOnly covers SOAR-9.
//
// A routing table that sends everything everywhere is not routing; the property is that a rule SELECTS,
// and that an unmatched notification still reaches somebody rather than being dropped.
func TestAlertRoutingSendsToTheSelectedSinkOnly(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	pager := startSink(t, http.StatusOK)
	archive := startSink(t, http.StatusOK)

	routes := filepath.Join(t.TempDir(), "routes.json")
	// Incidents go to the pager ONLY. Everything else is unmatched and fans out.
	if err := os.WriteFile(routes,
		[]byte(`[{"kinds":["incident"],"sinks":["pager"]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	setDynamic(t, stack, "OPENSHIELD_ALERT_WEBHOOK",
		"pager=http://"+pager.addr+"/p,archive=http://"+archive.addr+"/a")
	setDynamic(t, stack, "OPENSHIELD_ALERT_ROUTES", routes)
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	seedBurst(t, stack, "subject-routed", 5, 0.95)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("alert routing ACTIVE", 90*time.Second)

	Eventually(t, 90*time.Second, "the incident to reach the routed sink", func() bool {
		return pager.count() > 0
	})
	time.Sleep(3 * time.Second)
	if archive.count() > 0 {
		t.Errorf("an incident reached the UNROUTED sink (%d deliveries of %v) — a rule that selects one "+
			"sink and delivers to both is not a routing table, it is a fan-out with extra configuration",
			archive.count(), archive.kinds())
	}
}

// TestAFailingSinkIsRetriedAndNeverBreaksTheControlPlane covers SIEM-8.
func TestAFailingSinkIsRetriedAndNeverBreaksTheControlPlane(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	broken := startSink(t, http.StatusInternalServerError)

	setDynamic(t, stack, "OPENSHIELD_ALERT_WEBHOOK", "http://"+broken.addr+"/hook")
	setDynamic(t, stack, "OPENSHIELD_ALERT_RETRIES", "3")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	seedBurst(t, stack, "subject-retry", 5, 0.95)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("alert delivery enabled", 90*time.Second)

	// A 5xx is RETRIED — a transient blip during a deploy must not silently drop a page.
	Eventually(t, 90*time.Second, "the failing sink to be retried", func() bool {
		return broken.count() >= 2
	})

	// AND THE CONTROL PLANE KEEPS WORKING. Delivery is best-effort precisely so a down pager cannot
	// take detection down with it: the incident must still be in the database.
	pool := openPool(t, stack.DSN)
	var n int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM incidents WHERE subject_id='subject-retry'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Errorf("no incident was recorded while the pager was failing — a down sink must never break "+
			"the record it exists to announce\n%s", srv.Output())
	}
}
