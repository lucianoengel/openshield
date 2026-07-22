package controlplane

import (
	"net/http/httptest"
	"testing"
)

// SIEM-1 / SEC-8: the /events filter caps the limit — an uncapped query over the largest
// table is an unbounded-memory vector. A request for more than the cap is clamped, not honored,
// and a request within it is honored exactly. (In-package: parseEventFilter is unexported.)
func TestParseEventFilterCapsLimit(t *testing.T) {
	over := httptest.NewRequest("GET", "/events?limit=1000000", nil)
	f, err := parseEventFilter(over)
	if err != nil {
		t.Fatal(err)
	}
	if f.Limit != maxSearchLimit {
		t.Errorf("limit for a 1,000,000 ask = %d, want the cap %d", f.Limit, maxSearchLimit)
	}

	under := httptest.NewRequest("GET", "/events?limit=25", nil)
	f2, _ := parseEventFilter(under)
	if f2.Limit != 25 {
		t.Errorf("limit for a 25 ask = %d, want 25 (honored below the cap)", f2.Limit)
	}

	// A malformed limit is a hard error (SEC-8), not a silent fallback to the default.
	bad := httptest.NewRequest("GET", "/events?limit=notanumber", nil)
	if _, err := parseEventFilter(bad); err == nil {
		t.Error("a non-numeric limit must error, not silently fall back")
	}
}
