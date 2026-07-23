package controlplane_test

import (
	"net/http"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// TestListEndpointsRejectMalformedLimit (SEC-8): a non-integer or non-positive `limit` on the operator
// list endpoints (/alerts, /incidents) is a 400, not a silent fall-back to the default — a bad limit must
// never yield a truncated/defaulted list presented as authoritative. An absent or valid limit succeeds.
//
// Mutation: reverting either handler to the silent `queryInt` (default on parse failure) turns the
// malformed-limit cases into 200 — the 400 assertions FAIL.
func TestListEndpointsRejectMalformedLimit(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)
	op := clientWith(t, ca, "alice", "operator")

	status := func(path string) int {
		t.Helper()
		resp, err := op.Get("https://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	for _, ep := range []string{"/alerts", "/incidents"} {
		// Malformed and non-positive limits → 400.
		for _, bad := range []string{"?limit=abc", "?limit=-5", "?limit=0"} {
			if got := status(ep + bad); got != http.StatusBadRequest {
				t.Errorf("GET %s%s = %d, want 400 (a malformed limit must not silently default)", ep, bad, got)
			}
		}
		// A valid limit and an absent limit → 200 (the default still applies when absent).
		if got := status(ep + "?limit=5"); got != http.StatusOK {
			t.Errorf("GET %s?limit=5 = %d, want 200", ep, got)
		}
		if got := status(ep); got != http.StatusOK {
			t.Errorf("GET %s (no limit) = %d, want 200 (default applies)", ep, got)
		}
	}
}
