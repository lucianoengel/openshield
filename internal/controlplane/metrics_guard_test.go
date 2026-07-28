package controlplane

import (
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// EVERY DECLARED COUNTER MUST BE EXPOSED (D348).
//
// Eight counters were incremented and rendered by nothing — the whole external-log ingest path (CEF,
// CloudTrail, WEF), entity-graph resolve failures, and retention record failures. Each was written
// with a comment saying it existed so a discard would not be silent, and one carried a comment
// claiming it was already on /metrics and that dashboards depended on it.
//
// They did not go missing at once. They accumulated one at a time, each added by someone who
// reasonably assumed the metrics surface already covered it — which is exactly what will happen again
// unless something refuses it. This is that something.
//
// REFLECTION RATHER THAN A HAND-MAINTAINED LIST, deliberately: a list is a second thing to forget, and
// forgetting it looks identical to the bug being fixed.
func TestEveryDeclaredCounterIsExposedOnMetrics(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if body == "" {
		t.Fatal("the metrics handler produced no output, so this guard would pass vacuously")
	}

	// A counter is considered exposed if the handler reads it. Matching on the FIELD NAME rather than a
	// guessed metric name keeps the guard independent of naming conventions — the question is whether
	// the value reaches the surface, not what it is called there.
	src := metricsSource(t)

	typ := reflect.TypeOf(Server{})
	var missing []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type != reflect.TypeOf(atomic.Int64{}) {
			continue
		}
		if !f.IsExported() {
			continue // an unexported counter is internal bookkeeping, not an operator-facing signal
		}
		if !strings.Contains(src, "s."+f.Name+".Load()") {
			missing = append(missing, f.Name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d counter(s) are declared on Server and never rendered on /metrics: %v\n"+
			"A counter exists so a discard is not silent. One that is incremented and never exposed "+
			"gives the appearance of that property and none of its substance — and the failure is "+
			"invisible precisely because the counter looks present in the code. Add it to "+
			"MetricsHandler, or if it genuinely must not be exposed, say why beside the field.",
			len(missing), missing)
	}
}

// TestTheExposedCountersRenderWithHelpAndType keeps the guard above honest: it asserts that reading a
// counter in the handler actually produces Prometheus output, so "referenced in the source" cannot
// drift from "served to an operator".
func TestTheExposedCountersRenderWithHelpAndType(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	for _, name := range []string{
		"openshield_cef_dropped_total",
		"openshield_cloudtrail_dropped_total",
		"openshield_wef_dropped_total",
		"openshield_entity_resolve_failures_total",
		"openshield_retention_record_failures_total",
	} {
		if !strings.Contains(body, "# HELP "+name+" ") {
			t.Errorf("%s has no HELP line — an operator seeing the number for the first time at 3am "+
				"should not have to read the source to know whether it matters", name)
		}
		if !strings.Contains(body, "# TYPE "+name+" counter") {
			t.Errorf("%s has no TYPE line", name)
		}
	}
}

// metricsSource reads the handler's own source. The guard asks a question about the CODE — "is this
// field read here" — which cannot be answered by calling the handler, since an unexposed counter and
// a counter that happens to be zero produce identical output.
func metricsSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatalf("reading the metrics handler source: %v", err)
	}
	return string(b)
}
