package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/runner"
)

// SOAR-8 increment 2: incident ⇄ ticket sync.
//
// The acceptance criterion is "closing the ticket transitions the incident". The properties that matter
// beyond it are all about NOT over-reaching: an unrecognised remote status must not close an incident, a
// reopened ticket must not reopen one, and a machine must not be recorded as the human who acknowledged it.

// itsmServer is a stand-in ticketing system.
type itsmServer struct {
	*httptest.Server
	mu       sync.Mutex
	statuses map[string]string // ref → status
	creates  atomic.Int64
	bodies   []string
}

func newITSMServer(t *testing.T) *itsmServer {
	t.Helper()
	s := &itsmServer{statuses: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			ref := "TKT-" + string(rune('A'+int(s.creates.Load())))
			s.creates.Add(1)
			s.mu.Lock()
			s.bodies = append(s.bodies, string(buf[:n]))
			s.statuses[ref] = "open"
			s.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"ref": ref, "url": "https://itsm.example/" + ref})
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/tickets/")
		s.mu.Lock()
		st := s.statuses[ref]
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"status": st})
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *itsmServer) setStatus(ref, status string) {
	s.mu.Lock()
	s.statuses[ref] = status
	s.mu.Unlock()
}

func (s *itsmServer) firstBody() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bodies) == 0 {
		return ""
	}
	return s.bodies[0]
}

func itsmConnector(base string) *runner.ITSMConnector {
	return &runner.ITSMConnector{
		Name:     "tickets",
		Endpoint: base + "/tickets",
		Token:    "t0ken",
		// The CLOSED vocabulary of remote statuses that mean closed.
		ClosedStatuses: []string{"closed", "resolved"},
		MinSeverity:    controlplane.SeverityHigh,
		Timeout:        5 * time.Second,
	}
}

// TestClosingTheTicketTransitionsTheIncident is SOAR-8(a)'s acceptance criterion, plus the
// one-ticket-per-incident property.
//
// Mutation: do not transition on a closed status → FAILS.
func TestClosingTheTicketTransitionsTheIncident(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	itsm := newITSMServer(t)
	conn := itsmConnector(itsm.URL)
	ctx := context.Background()

	incID := seedIncident(t, pool, "cross_domain", "subject-itsm", 0.92, []string{"dlp"})
	// Below the floor: never ticketed.
	lowID := seedIncident(t, pool, "cross_domain", "subject-itsm-low", 0.30, nil)

	if err := srv.SyncITSM(ctx, conn); err != nil {
		t.Fatalf("sync: %v", err)
	}
	tk, err := srv.TicketForIncident(ctx, conn.Name, incID)
	if err != nil || tk == nil {
		t.Fatalf("no ticket opened for a matching incident: %+v err=%v", tk, err)
	}
	if low, _ := srv.TicketForIncident(ctx, conn.Name, lowID); low != nil {
		t.Errorf("a below-floor incident was ticketed: %+v", low)
	}

	// Repeated syncs must not open a second ticket in someone else's system.
	for i := 0; i < 3; i++ {
		if err := srv.SyncITSM(ctx, conn); err != nil {
			t.Fatalf("repeat sync %d: %v", i, err)
		}
	}
	if n := itsm.creates.Load(); n != 1 {
		t.Errorf("%d tickets created across 4 syncs, want 1", n)
	}

	// The ticket body carries METADATA ONLY — a ticketing system is usually the least access-controlled
	// place an incident ever reaches.
	body := itsm.firstBody()
	if !strings.Contains(body, "subject-itsm") || !strings.Contains(body, "critical") {
		t.Errorf("ticket body %q lacks the pseudonymous subject or severity", body)
	}

	// THE ACCEPTANCE CASE: closing the ticket closes the incident.
	itsm.setStatus(tk.Ref, "resolved")
	if err := srv.SyncITSM(ctx, conn); err != nil {
		t.Fatalf("sync after close: %v", err)
	}
	var state, by string
	if err := pool.QueryRow(ctx, `SELECT state, coalesce(transitioned_by,'') FROM incidents WHERE id=$1`,
		incID).Scan(&state, &by); err != nil {
		t.Fatal(err)
	}
	if state != controlplane.IncidentClosed {
		t.Errorf("the incident is %q after its ticket was resolved, want closed — the incident and the "+
			"ticket drift apart, which is the whole reason this exists", state)
	}
	// THE CONNECTOR IS THE ACTOR. TransitionIncident stamps the acknowledgement on the first move off
	// `open` (D258), so a machine must not be recorded as the human who acknowledged it.
	if by != "itsm:tickets" {
		t.Errorf("transitioned_by = %q, want itsm:tickets", by)
	}
	var ackBy string
	if err := pool.QueryRow(ctx, `SELECT acknowledged_by FROM incidents WHERE id=$1`, incID).Scan(&ackBy); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ackBy, "itsm:") {
		t.Errorf("acknowledged_by = %q — a machine's decision recorded under a person's name is a "+
			"corrupted audit trail, and it corrupts the acknowledgement attribution response metrics rest on", ackBy)
	}
}

// TestUnknownRemoteStatusDoesNotCloseAnIncident.
//
// Mutation: treat any status that is not "open" as closed → FAILS. The fail-safe direction is "keep
// investigating": if a remote system renames a status, an incident must not silently stop being worked.
func TestUnknownRemoteStatusDoesNotCloseAnIncident(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	itsm := newITSMServer(t)
	conn := itsmConnector(itsm.URL)
	ctx := context.Background()

	incID := seedIncident(t, pool, "cross_domain", "subject-itsm-unknown", 0.95, nil)
	if err := srv.SyncITSM(ctx, conn); err != nil {
		t.Fatal(err)
	}
	tk, _ := srv.TicketForIncident(ctx, conn.Name, incID)

	// A status this connector does not declare — a renamed workflow state, a vendor change, a typo.
	itsm.setStatus(tk.Ref, "Done (Won't Fix)")
	if err := srv.SyncITSM(ctx, conn); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM incidents WHERE id=$1`, incID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state == controlplane.IncidentClosed {
		t.Error("an UNRECOGNISED remote status closed the incident — a vocabulary change in someone else's " +
			"system silently stopped this being investigated")
	}
	// But the observed status IS recorded, so an operator can see the unmapped value rather than
	// wondering why nothing ever closes.
	tk, _ = srv.TicketForIncident(ctx, conn.Name, incID)
	if tk.LastStatus != "Done (Won't Fix)" {
		t.Errorf("last_status = %q, want the unrecognised value recorded", tk.LastStatus)
	}
}

// TestReopenedTicketDoesNotReopenTheIncident — forward-only survives contact with an external system.
//
// D250 made the lifecycle forward-only so MTTA/MTTR stay measurable, and an incident that needs reopening
// becomes a NEW incident. An external system does not get to override an invariant the metrics depend on.
func TestReopenedTicketDoesNotReopenTheIncident(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	itsm := newITSMServer(t)
	conn := itsmConnector(itsm.URL)
	ctx := context.Background()

	incID := seedIncident(t, pool, "cross_domain", "subject-itsm-reopen", 0.95, nil)
	if err := srv.SyncITSM(ctx, conn); err != nil {
		t.Fatal(err)
	}
	tk, _ := srv.TicketForIncident(ctx, conn.Name, incID)
	itsm.setStatus(tk.Ref, "closed")
	if err := srv.SyncITSM(ctx, conn); err != nil {
		t.Fatal(err)
	}

	// A human reopens the ticket.
	itsm.setStatus(tk.Ref, "open")
	if err := srv.SyncITSM(ctx, conn); err != nil {
		t.Fatalf("a reopened ticket made the sync fail: %v — reopening is a legitimate thing to do, it "+
			"simply does not move this incident", err)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM incidents WHERE id=$1`, incID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != controlplane.IncidentClosed {
		t.Errorf("the incident moved to %q when its ticket reopened — the forward-only lifecycle is what "+
			"makes response time measurable, and an external system must not override it", state)
	}
}

// TestMeansClosedIsAClosedVocabulary — the pure predicate, exhaustively.
func TestMeansClosedIsAClosedVocabulary(t *testing.T) {
	conn := itsmConnector("http://example.invalid")
	for _, s := range []string{"closed", "CLOSED", " Resolved ", "resolved"} {
		if !conn.MeansClosed(s) {
			t.Errorf("%q should mean closed", s)
		}
	}
	for _, s := range []string{"", "open", "in progress", "done", "cancelled", "closed-ish", "resolve"} {
		if conn.MeansClosed(s) {
			t.Errorf("%q was treated as closed — anything outside the declared set must be IGNORED, "+
				"because the fail-safe direction is 'keep investigating'", s)
		}
	}
}
