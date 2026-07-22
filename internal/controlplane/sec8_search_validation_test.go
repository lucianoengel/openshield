package controlplane_test

import (
	"net/http"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SEC-8: /search returns 400 on a malformed filter param instead of silently dropping it
// (a silent drop yields over-broad results that look authoritative), and caps the limit.
func TestSearchRejectsMalformedParams(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)
	op := clientWith(t, ca, "alice", "operator")

	bad := []string{
		"/search?min_risk=notanumber",
		"/search?since=notatime",
		"/search?until=2026-13-99",
		"/search?limit=abc",
		"/search?limit=-5",
	}
	for _, path := range bad {
		resp, err := op.Get("https://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400 (malformed filter must not be silently dropped)", path, resp.StatusCode)
		}
	}

	// A well-formed search still succeeds (200), and an oversized limit is accepted (capped),
	// not rejected — a big ask is honored up to the cap.
	for _, path := range []string{"/search?min_risk=0.5", "/search?limit=100000"} {
		resp, err := op.Get("https://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}
}
