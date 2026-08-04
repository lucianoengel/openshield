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
	// EVERY MOUNTED ROUTE, READ OUT OF THE MOUNT ITSELF (CONSOLE-1). This used to be six paths written
	// by hand, which meant the check covered whatever someone remembered to add — and a route nobody
	// remembered is exactly the failure being guarded against. The list now comes from the same outer
	// mux the guard in operator_route_closure_test.go parses, so a route cannot be added without being
	// covered here.
	//
	// GET ONLY, deliberately: every mutating route rejects a GET with 405, so this walks the whole
	// surface without opening a case, publishing an intent or launching a backfill against the fixture
	// database. A mounted route answers SOMETHING — 200, 400 for a missing parameter, 403 for a tier or
	// the privacy authority it lacks, 405 for the wrong method. Only 404 means it was never mounted.
	mounted := mountedOperatorRoutes(t)
	if len(mounted) < 30 {
		t.Fatalf("read only %d mounted routes out of enroll_http.go — the parse is wrong and this test "+
			"proves nothing", len(mounted))
	}
	for _, path := range mounted {
		resp, err := op.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("operator GET %s = 404 — route registered on the inner mux but not mounted on the served mux", path)
		}
		// AND IT IS GATED. Without this, a route accidentally mounted OUTSIDE requireTier would pass the
		// loop above perfectly — it would answer, which is all the 404 check asks for.
		anon := clientWith(t, ca, "nobody", "")
		aresp, aerr := anon.Get("https://" + addr + path)
		if aerr != nil {
			t.Fatalf("anonymous GET %s: %v", path, aerr)
		}
		aresp.Body.Close()
		if aresp.StatusCode != http.StatusUnauthorized && aresp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s with a role-less certificate = %d — an operator route must refuse an "+
				"unauthorized caller, not serve them", path, aresp.StatusCode)
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
