package controlplane_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
)

// capturingWebhook records every notification POSTed to it, decoded from the JSON body.
type capturingWebhook struct {
	mu  sync.Mutex
	got []notify.Notification
	srv *httptest.Server
}

func newCapturingWebhook(t *testing.T) *capturingWebhook {
	t.Helper()
	c := &capturingWebhook{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var n notify.Notification
		_ = json.Unmarshal(body, &n)
		c.mu.Lock()
		c.got = append(c.got, n)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *capturingWebhook) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func (c *capturingWebhook) snapshot() []notify.Notification {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]notify.Notification, len(c.got))
	copy(out, c.got)
	return out
}

// TestMaterializeNewIncidentNotifiesOnce (SOAR-1 / audit test #10): materializing a NEW incident pages
// exactly once through the real emit→deliverLoop→webhook path, and re-materializing the SAME open
// incident (the extend-the-burst UPDATE path) pages ZERO more. Drives MaterializeIncidents twice
// against real Postgres and a real httptest webhook — no seeded literals, no direct emit call.
//
// Mutation A (ignore the RETURNING (xmax=0) `inserted` flag, always emit): the re-materialize delivers
// a second POST → this test FAILs on `want exactly 1`.
func TestMaterializeNewIncidentNotifiesOnce(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_soar1_%d", now.UnixNano())

	hook := newCapturingWebhook(t)
	srv.SetNotifier(notify.NewWebhook(hook.srv.URL))

	seed := func(risk float64, ago time.Duration) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,$2,'v1','agent-a',$3)`, subject, risk, now.Add(-ago)); err != nil {
			t.Fatal(err)
		}
	}
	seed(0.90, 1*time.Minute)
	seed(0.95, 5*time.Minute)
	seed(0.80, 10*time.Minute)

	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}

	// First materialize creates the incident → exactly one page.
	if n, err := srv.MaterializeIncidents(ctx, rule, now); err != nil || n != 1 {
		t.Fatalf("materialize = %d, %v; want 1", n, err)
	}
	waitFor(t, func() bool { return hook.count() >= 1 })

	// The page carries the incident kind, the subject, and an inc_<id> idempotency key.
	got := hook.snapshot()
	if len(got) != 1 {
		t.Fatalf("after first materialize: %d POSTs, want 1", len(got))
	}
	if got[0].Kind != notify.KindIncident {
		t.Errorf("notification kind = %q, want %q", got[0].Kind, notify.KindIncident)
	}
	if got[0].Subject != subject {
		t.Errorf("notification subject = %q, want %q", got[0].Subject, subject)
	}
	if len(got[0].ID) < 4 || got[0].ID[:4] != "inc_" {
		t.Errorf("notification id = %q, want an inc_<id> key", got[0].ID)
	}

	// Re-materialize the SAME open incident (a fresh alert extends the burst → the DO UPDATE path).
	seed(0.99, 30*time.Second)
	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	// Give any erroneous second delivery time to arrive, then assert still exactly one.
	time.Sleep(500 * time.Millisecond)
	if c := hook.count(); c != 1 {
		t.Fatalf("after re-materializing the same open incident: %d POSTs, want exactly 1 "+
			"(the extend-the-burst UPDATE must not re-page)", c)
	}
	// The insert-vs-update guard means the UPDATE path never even reaches emit — so nothing was
	// suppressed by the dedup either. If the guard is dropped (always emit), the redundant emit hits
	// the id-dedup and this counter climbs — making the otherwise-invisible guard observable. (Absent
	// the counter check, the durable inc_<id> dedup would mask an always-emit regression at the sink.)
	if d := srv.NotifyDeduped.Load(); d != 0 {
		t.Fatalf("NotifyDeduped = %d, want 0 — the update path emitted a redundant notification "+
			"instead of being skipped by the insert-vs-update guard", d)
	}
}

// TestDistinctLaterIncidentPagesAgain proves the idempotency key is per-INCIDENT, not per-content-window
// (SOAR-1): a NEW incident for the same subject — raised after the first left the open state — pages
// again, even inside the 10-minute content-window bucket that would collapse a kind|subject|window key.
//
// Mutation B (drop the explicit inc_<id> ID so emit falls back to the content-window notifyID): both
// incidents fall in the same kind|subject|window bucket → the second is suppressed → this test FAILs.
func TestDistinctLaterIncidentPagesAgain(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("sub_soar1b_%d", now.UnixNano())

	hook := newCapturingWebhook(t)
	srv.SetNotifier(notify.NewWebhook(hook.srv.URL))

	seed := func(risk float64, ago time.Duration) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at)
			 VALUES ($1,$2,'v1','agent-a',$3)`, subject, risk, now.Add(-ago)); err != nil {
			t.Fatal(err)
		}
	}
	rule := controlplane.CorrelationRule{Window: time.Hour, MinAlerts: 3}

	// Incident #1 → one page.
	seed(0.90, 1*time.Minute)
	seed(0.95, 2*time.Minute)
	seed(0.80, 3*time.Minute)
	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return hook.count() >= 1 })

	// Move it out of the open state so a later burst opens a DISTINCT incident (new autoincrement id).
	stored, err := srv.RecentIncidents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var firstID int64
	for _, s := range stored {
		if s.SubjectID == subject && s.State == "open" {
			firstID = s.ID
		}
	}
	if firstID == 0 {
		t.Fatal("no open incident found to acknowledge")
	}
	if _, err := srv.AcknowledgeIncident(ctx, firstID, "operator:alice"); err != nil {
		t.Fatal(err)
	}

	// A fresh burst for the same subject, still inside the same content-window, opens a NEW incident.
	seed(0.97, 30*time.Second)
	seed(0.98, 20*time.Second)
	seed(0.99, 10*time.Second)
	if _, err := srv.MaterializeIncidents(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	// The distinct new incident must page again (per-incident dedup, not per-window).
	waitFor(t, func() bool { return hook.count() >= 2 })

	got := hook.snapshot()
	if len(got) < 2 {
		t.Fatalf("distinct later incident did not page: %d POSTs, want 2", len(got))
	}
	if got[0].ID == got[1].ID {
		t.Errorf("both pages share id %q — the key is not per-incident (content-window collision)", got[0].ID)
	}
}
