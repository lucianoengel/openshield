//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// EXTERNAL LOG INGEST AND THE INTEGRATION RUNNERS (D304).
//
// SIEM-4 is what makes OpenShield a SIEM rather than a store of its own telemetry: it ingests the
// estate's third-party logs. SOAR-8 is what makes the response leave the platform — a ticket in
// somebody's queue, an account disabled in somebody's IdP.
//
// Both are the shape this session keeps finding dangerous: a listener or a poller that comes up
// silently and does nothing, or a connector that reports success it never achieved. The control plane
// treats both as best-effort — a scan error is logged and never fatal — so every failure here is quiet.

// itsmServer is a stand-in ticketing system that records what was opened and answers status queries.
type itsmServer struct {
	mu      sync.Mutex
	opened  []map[string]any
	status  string
	addr    string
	authSaw string
}

func startITSM(t *testing.T) *itsmServer {
	t.Helper()
	s := &itsmServer{status: "open"}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.authSaw = r.Header.Get("Authorization")
		s.mu.Unlock()
		if r.Method == http.MethodGet {
			s.mu.Lock()
			st := s.status
			s.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"status": st})
			return
		}
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		s.mu.Lock()
		s.opened = append(s.opened, m)
		ref := fmt.Sprintf("TICKET-%d", len(s.opened))
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"ref": ref, "url": "http://tickets/" + ref})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

func (s *itsmServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.opened)
}

// TestAnIncidentOpensAndClosesAnITSMTicket covers SOAR-8(a) both ways.
//
// Both directions matter and only one is obvious: opening a ticket is the visible half, and SYNC-BACK —
// a ticket closed in the remote system closing the incident here — is what stops the two queues drifting
// until nobody trusts either.
func TestAnIncidentOpensAndClosesAnITSMTicket(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	tickets := startITSM(t)

	setDynamic(t, stack, "OPENSHIELD_ITSM_ENDPOINT", "http://"+tickets.addr+"/tickets")
	setDynamic(t, stack, "OPENSHIELD_ITSM_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_ITSM_MIN_SEVERITY", "high")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	seedBurst(t, stack, "subject-ticketed", 5, 0.95)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_ITSM_TOKEN=integration-token",
	})
	srv.WaitForOutput("ITSM sync ACTIVE", 90*time.Second)

	Eventually(t, 90*time.Second, "a ticket to be opened for the incident", func() bool {
		return tickets.count() > 0
	})
	tickets.mu.Lock()
	first, auth := tickets.opened[0], tickets.authSaw
	tickets.mu.Unlock()
	if auth != "Bearer integration-token" {
		t.Errorf("the ticket request carried %q — an unauthenticated call to a ticketing system either "+
			"fails or, worse, succeeds against an open one", auth)
	}
	// PSEUDONYMOUS. A ticket lands in a system outside this platform's retention and access controls.
	if s, _ := first["subject"].(string); s != "subject-ticketed" {
		t.Errorf("the ticket names subject %q", s)
	}
	body, _ := json.Marshal(first)
	if contains(string(body), "111.444.777") {
		t.Errorf("the ticket carries evidence content:\n%s", body)
	}

	// ONE TICKET, not one per sync tick.
	time.Sleep(5 * time.Second)
	if n := tickets.count(); n != 1 {
		t.Errorf("%d tickets were opened for ONE incident — a sync loop that re-opens on every tick "+
			"fills someone else's queue with duplicates", n)
	}

	// SYNC BACK: closing the ticket remotely closes the incident here.
	tickets.mu.Lock()
	tickets.status = "closed"
	tickets.mu.Unlock()
	pool := openPool(t, stack.DSN)
	Eventually(t, 90*time.Second, "the incident to close when its ticket closes", func() bool {
		var state string
		_ = pool.QueryRow(Ctx(t),
			`SELECT state FROM incidents WHERE subject_id='subject-ticketed'`).Scan(&state)
		return state == "closed"
	})
}

// TestAnUnknownRemoteStatusNeverClosesAnIncident is the fail-safe direction.
//
// If a remote system renames a status or returns something unexpected, the safe answer is "keep
// investigating" — not "stop". A connector that treated anything-but-open as closed would silently end
// investigations whenever a vendor changed a string.
func TestAnUnknownRemoteStatusNeverClosesAnIncident(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	tickets := startITSM(t)
	tickets.mu.Lock()
	tickets.status = "pending-triage" // not in the closed vocabulary
	tickets.mu.Unlock()

	setDynamic(t, stack, "OPENSHIELD_ITSM_ENDPOINT", "http://"+tickets.addr+"/tickets")
	setDynamic(t, stack, "OPENSHIELD_ITSM_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	seedBurst(t, stack, "subject-unknown-status", 5, 0.95)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("ITSM sync ACTIVE", 90*time.Second)
	Eventually(t, 90*time.Second, "the ticket to be opened", func() bool { return tickets.count() > 0 })
	time.Sleep(5 * time.Second)

	pool := openPool(t, stack.DSN)
	var state string
	if err := pool.QueryRow(Ctx(t),
		`SELECT state FROM incidents WHERE subject_id='subject-unknown-status'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state == "closed" {
		t.Errorf("an UNKNOWN remote status closed the incident — anything outside the closed vocabulary "+
			"must be ignored, or a vendor renaming a status ends investigations here\n%s", srv.Output())
	}
}

// TestCloudTrailAndWEFFilesAreIngested covers SIEM-4's directory pollers.
func TestCloudTrailAndWEFFilesAreIngested(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	ctDir, wefDir := t.TempDir(), t.TempDir()

	const trail = `{"Records":[{"eventTime":"2026-07-27T10:00:00Z","eventSource":"s3.amazonaws.com",` +
		`"eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.5",` +
		`"userIdentity":{"arn":"arn:aws:iam::1:user/alice"}}]}`
	if err := os.WriteFile(filepath.Join(ctDir, "trail.json"), []byte(trail), 0o600); err != nil {
		t.Fatal(err)
	}
	const wef = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
		`<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>` +
		`<TimeCreated SystemTime="2026-07-27T10:00:00Z"/><Computer>WS-01</Computer></System>` +
		`<EventData><Data Name="TargetUserName">bob</Data></EventData></Event>`
	if err := os.WriteFile(filepath.Join(wefDir, "sec.xml"), []byte(wef), 0o600); err != nil {
		t.Fatal(err)
	}

	setDynamic(t, stack, "OPENSHIELD_CLOUDTRAIL_DIR", ctDir)
	setDynamic(t, stack, "OPENSHIELD_WEF_DIR", wefDir)
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("CloudTrail ingest watching", 90*time.Second)
	srv.WaitForOutput("WEF ingest watching", 60*time.Second)
	pool := openPool(t, stack.DSN)

	for _, want := range []struct{ product, marker string }{
		{"cloudtrail", "GetObject"},
		{"windows", "4625"},
	} {
		w := want
		Eventually(t, 120*time.Second, "the "+w.product+" record to be ingested", func() bool {
			var n int
			_ = pool.QueryRow(Ctx(t),
				`SELECT count(*) FROM external_logs WHERE product=$1`, w.product).Scan(&n)
			return n > 0
		})
	}

	// The ingested record must be SEARCHABLE by its normalised fields — ingest that stores an opaque
	// blob is archival, not a SIEM, and the whole point of SIEM-4 is hunting across sources.
	var name, sig string
	if err := pool.QueryRow(Ctx(t),
		`SELECT name, signature_id FROM external_logs WHERE product='cloudtrail' LIMIT 1`).
		Scan(&name, &sig); err != nil {
		t.Fatal(err)
	}
	if name == "" && sig == "" {
		t.Error("the CloudTrail record was stored with no normalised name or signature — a row that can " +
			"only be found by its raw text is not searchable across sources")
	}
}

// TestTheClosedVocabularyBelongsToTheOperator covers OPENSHIELD_ITSM_CLOSED_STATUSES and
// OPENSHIELD_ITSM_NAME — the two settings that decide whether sync-back works at all in a deployment
// whose ticketing system does not happen to speak the shipped default.
//
// `TestAnUnknownRemoteStatusNeverClosesAnIncident` above proves the fail-safe direction, but it runs on
// the DEFAULT vocabulary, so it would pass unchanged against a build that ignored the setting and
// hardcoded `closed,resolved,done`. In a German or Portuguese service desk that build closes nothing
// ever: tickets get resolved, incidents stay open, and the two queues drift until an operator stops
// trusting the one they did not close by hand — the exact failure the sync exists to prevent, arriving
// silently.
//
// So this configures a vocabulary of ONE word that is not in the default, and checks both directions.
// The negative is the load-bearing half: a DEFAULT word must NOT close the incident, because the
// configured list REPLACES the default rather than extending it. A hardcoded implementation fails there.
func TestTheClosedVocabularyBelongsToTheOperator(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	tickets := startITSM(t)

	setDynamic(t, stack, "OPENSHIELD_ITSM_ENDPOINT", "http://"+tickets.addr+"/tickets")
	setDynamic(t, stack, "OPENSHIELD_ITSM_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_ITSM_CLOSED_STATUSES", "erledigt")
	setDynamic(t, stack, "OPENSHIELD_ITSM_NAME", "servicedesk-eu")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	seedBurst(t, stack, "subject-vocabulary", 5, 0.95)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("ITSM sync ACTIVE", 90*time.Second)
	Eventually(t, 90*time.Second, "a ticket to be opened", func() bool { return tickets.count() > 0 })

	pool := openPool(t, stack.DSN)
	// The connector NAME is recorded on the ticket link. It is how a deployment with two ticketing
	// systems tells which one owns a ticket; a hardcoded name makes those two rows collide.
	var connector string
	if err := pool.QueryRow(Ctx(t), `SELECT connector FROM itsm_tickets LIMIT 1`).Scan(&connector); err != nil {
		t.Fatal(err)
	}
	if connector != "servicedesk-eu" {
		t.Errorf("the ticket is recorded against connector %q, not the configured name — with two "+
			"ticketing systems configured, neither one's tickets could be told from the other's", connector)
	}

	state := func() string {
		var s string
		if err := pool.QueryRow(Ctx(t),
			`SELECT state FROM incidents WHERE subject_id='subject-vocabulary'`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// A word from the SHIPPED DEFAULT vocabulary, which this deployment has not configured.
	tickets.mu.Lock()
	tickets.status = "closed"
	tickets.mu.Unlock()
	time.Sleep(5 * time.Second)
	if s := state(); s == "closed" {
		t.Fatalf("the remote status %q closed the incident although the configured vocabulary is "+
			"'erledigt'. The operator's list REPLACES the default; a build that also honours the "+
			"built-in words closes incidents on a status this deployment never agreed means closed\n%s",
			"closed", srv.Output())
	}

	// And the word the operator DID configure closes it.
	tickets.mu.Lock()
	tickets.status = "erledigt"
	tickets.mu.Unlock()
	Eventually(t, 90*time.Second, "the CONFIGURED closed status to close the incident", func() bool {
		return state() == "closed"
	})
}

// hungITSM accepts connections and never answers, counting how many requests it received.
func hungITSM(t *testing.T) (addr string, requests func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	var mu sync.Mutex
	n := 0
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		select {
		case <-block:
		case <-r.Context().Done(): // the client gave up — which is the point
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { close(block); _ = srv.Close() })
	return ln.Addr().String(), func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// TestAHungTicketingSystemDoesNotWedgeTheSyncLoop covers OPENSHIELD_ITSM_TIMEOUT.
//
// A third-party SaaS that accepts a connection and then never answers is the ordinary failure of an
// outbound integration, and it is the one with no error to log. Without a timeout the sync loop parks on
// a single request forever: no ticket is ever opened again, no incident is ever closed again, and the
// only symptom is that the queue quietly stops moving.
//
// THE ASSERTION IS THE RETRY RATE, because the connector has a 10-second fallback of its own. A loop
// honouring a configured 1-second timeout retries about ten times in the window below; one that fell
// back to 10 seconds manages one or two. That difference is what distinguishes "the setting is wired"
// from "something else saved us" — the mutation to catch is the wiring dropping `Timeout:`, not the
// absence of any timeout at all.
func TestAHungTicketingSystemDoesNotWedgeTheSyncLoop(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	addr, requests := hungITSM(t)

	setDynamic(t, stack, "OPENSHIELD_ITSM_ENDPOINT", "http://"+addr+"/tickets")
	setDynamic(t, stack, "OPENSHIELD_ITSM_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_ITSM_TIMEOUT", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_INTERVAL", "1s")
	setDynamic(t, stack, "OPENSHIELD_CORRELATE_MIN_ALERTS", "3")
	seedBurst(t, stack, "subject-hung-itsm", 5, 0.95)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("ITSM sync ACTIVE", 90*time.Second)

	const want = 5
	Eventually(t, 30*time.Second, "the sync loop to keep retrying against an unresponsive ticketing system",
		func() bool { return requests() >= want })

	// AND IT IS STILL GOING. Checking that the process is alive would be weaker: a control plane whose
	// ITSM loop has parked on a dead request is still a live process, and looks fine from outside. So the
	// assertion is that the count keeps CLIMBING after the threshold was met.
	before := requests()
	time.Sleep(4 * time.Second)
	if after := requests(); after <= before {
		t.Errorf("the sync loop stopped retrying after %d attempts — it reached the threshold and then "+
			"parked. A third-party integration that cannot answer must degrade the integration, never "+
			"stop the queue moving\n%s", before, srv.Output())
	}
}
