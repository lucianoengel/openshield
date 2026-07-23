package controlplane_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// TestMetricsHandlerBehindBearerGuard (PLAT-4b): the metrics endpoint as main.go WIRES it — the real
// MetricsHandler composed behind RequireBearerToken. TestRequireBearerToken tests the guard with a stub
// handler and TestMetricsHandler tests the handler unguarded; neither covers the composition main.go
// actually mounts. This proves the real metrics are served ONLY with a valid token, and that an
// unauthenticated scrape leaks NO operational counters.
//
// Mutation: dropping the RequireBearerToken wrap in the wiring (serving MetricsHandler directly) makes
// the no-token and wrong-token cases return 200 with the counters — the 401 + no-leak assertions FAIL.
func TestMetricsHandlerBehindBearerGuard(t *testing.T) {
	const token = "s3cret-scrape-token"
	srv := controlplane.New(nil) // MetricsHandler reads in-memory counters — no DB needed
	srv.RejectedTelemetry.Store(5)
	guarded := controlplane.RequireBearerToken(token, srv.MetricsHandler())

	get := func(auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		return rec
	}

	const counter = "openshield_rejected_telemetry_total"

	// No token → 401 and NO counter leaked.
	if rec := get(""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no-token scrape = %d, want 401", rec.Code)
	} else if strings.Contains(rec.Body.String(), counter) {
		t.Error("an unauthenticated scrape leaked the operational counters")
	}

	// Wrong token → 401.
	if rec := get("Bearer not-the-token"); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong-token scrape = %d, want 401", rec.Code)
	}

	// Correct token → 200 and the real metrics are served (the live counter value is present).
	if rec := get("Bearer " + token); rec.Code != http.StatusOK {
		t.Errorf("authenticated scrape = %d, want 200", rec.Code)
	} else if !strings.Contains(rec.Body.String(), counter+" 5") {
		t.Errorf("authenticated scrape did not serve the real metrics; body = %q", rec.Body.String())
	}
}
