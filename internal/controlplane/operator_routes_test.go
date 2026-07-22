package controlplane_test

import (
	"net/http"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-1 REOPEN + class guard: every operator-read route registered on the inner handler mux MUST
// also be mounted on the SERVED TLS mux. The /events endpoint was registered but never mounted, so
// it 404'd in production while its unit tests (calling SearchTelemetry directly) passed — the
// "verifies against its own assumptions" trap. This test hits the REAL served router with an
// operator cert (must not 404) and an agent cert on /events (must 403), so a missed mount fails.
func TestOperatorReadRoutesMountedAndGated(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)

	op := clientWith(t, ca, "alice", "operator")
	// Every operator-read GET route. A mounted route returns 200 (or a 4xx for a missing param),
	// never 404. A 404 means the route is registered on the inner mux but not served.
	for _, path := range []string{
		"/alerts", "/search", "/events", "/incidents", "/overdue", "/subject?id=s1",
	} {
		resp, err := op.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("operator GET %s = 404 — route registered on the inner mux but not mounted on the served mux", path)
		}
	}

	// The role gate still applies to the newly-mounted /events: an agent cert is refused.
	ag := clientWith(t, ca, "spy-agent", "agent")
	resp, err := ag.Get("https://" + addr + "/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("agent GET /events = %d, want 403", resp.StatusCode)
	}
}

// SIEM-11 (SEC-8): /incidents and /overdue reject a malformed param with 400, not a silent
// fall-back to the default that widens the result and looks authoritative.
func TestIncidentsAndOverdueRejectBadParams(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)
	op := clientWith(t, ca, "alice", "operator")

	for _, path := range []string{
		"/incidents?window=notaduration",
		"/incidents?min_alerts=0",
		"/incidents?min_risk=abc",
		"/overdue?threshold=notaduration",
	} {
		resp, err := op.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400 (malformed param silently accepted)", path, resp.StatusCode)
		}
	}
	// A well-formed request still succeeds.
	resp, _ := op.Get("https://" + addr + "/incidents?window=1h&min_alerts=3")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid /incidents = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}
