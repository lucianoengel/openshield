package controlplane

import (
	"net/http/httptest"
	"testing"
)

// TestParseExternalLogFilter (SIEM-4 / SEC-8): the /logs filter rejects a malformed since/until/limit
// rather than silently ignoring it (which would return over-broad results an investigator trusts), and
// parses a valid filter.
func TestParseExternalLogFilter(t *testing.T) {
	for _, q := range []string{
		"/logs?since=notatime",
		"/logs?until=nope",
		"/logs?limit=0",
		"/logs?limit=-5",
		"/logs?limit=abc",
	} {
		if _, err := parseExternalLogFilter(httptest.NewRequest("GET", q, nil)); err == nil {
			t.Errorf("parseExternalLogFilter(%q) accepted a malformed filter, want an error", q)
		}
	}
	f, err := parseExternalLogFilter(httptest.NewRequest("GET", "/logs?vendor=aws&product=cloudtrail&host=203.0.113.7&limit=25", nil))
	if err != nil {
		t.Fatalf("valid filter errored: %v", err)
	}
	if f.Vendor != "aws" || f.Product != "cloudtrail" || f.Host != "203.0.113.7" || f.Limit != 25 {
		t.Fatalf("valid filter mis-parsed: %+v", f)
	}
}
