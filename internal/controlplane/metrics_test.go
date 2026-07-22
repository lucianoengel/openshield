package controlplane_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// PLAT-4: /metrics exposes the operational counters in Prometheus text format, reflecting
// the live values — an operator can scrape and alert on the "no silent loss" counters.
func TestMetricsHandler(t *testing.T) {
	srv := controlplane.New(nil) // no DB needed — the handler reads in-memory counters
	srv.DroppedMessages.Store(7)
	srv.Gaps.Store(3)
	srv.RejectedTelemetry.Store(2)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	srv.MetricsHandler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// The live values are exposed.
	for _, want := range []string{
		"openshield_dropped_messages_total 7",
		"openshield_telemetry_gaps_total 3",
		"openshield_rejected_telemetry_total 2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n---\n%s", want, body)
		}
	}
	// Prometheus format: every metric has a HELP and TYPE line.
	if strings.Count(body, "# TYPE ") < 6 {
		t.Errorf("expected TYPE lines for each counter; got:\n%s", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain (Prometheus)", ct)
	}
}
