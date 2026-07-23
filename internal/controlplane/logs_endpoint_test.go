package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// TestLogsEndpointReturnsIngestedLogs (SIEM-4): GET /logs on the operator read mux returns the ingested
// third-party external logs (CEF/CloudTrail), filtered — the operator query surface over what D205/D208
// ingest. A malformed filter param is a 400 (SEC-8), not silently ignored.
func TestLogsEndpointReturnsIngestedLogs(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	// Two ingested logs from different vendors.
	if err := srv.InsertExternalLog(ctx, controlplane.ExternalLog{
		Vendor: "aws", Product: "cloudtrail", Name: "ConsoleLogin", SourceHost: "203.0.113.7", Severity: "",
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.InsertExternalLog(ctx, controlplane.ExternalLog{
		Vendor: "acme", Product: "firewall", Name: "Worm blocked", SourceHost: "10.0.0.1",
	}); err != nil {
		t.Fatal(err)
	}

	h := srv.OperatorReadHandler()

	// A vendor filter returns only the matching logs.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/logs?vendor=aws", nil))
	if rec.Code != 200 {
		t.Fatalf("/logs?vendor=aws = %d, want 200", rec.Code)
	}
	var got []controlplane.ExternalLog
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding /logs response: %v (%s)", err, rec.Body.String())
	}
	if len(got) != 1 || got[0].Name != "ConsoleLogin" || got[0].Product != "cloudtrail" {
		t.Fatalf("/logs?vendor=aws returned %+v, want the one CloudTrail log", got)
	}

	// A malformed filter param is a 400 (SEC-8), not a silent over-broad result.
	bad := httptest.NewRecorder()
	h.ServeHTTP(bad, httptest.NewRequest("GET", "/logs?since=notatime", nil))
	if bad.Code != 400 {
		t.Fatalf("/logs?since=notatime = %d, want 400", bad.Code)
	}
	if !strings.Contains(bad.Body.String(), "bad filter") {
		t.Errorf("400 body = %q, want a 'bad filter' message", bad.Body.String())
	}

	// A non-GET is rejected.
	post := httptest.NewRecorder()
	h.ServeHTTP(post, httptest.NewRequest("POST", "/logs", nil))
	if post.Code != 405 {
		t.Errorf("POST /logs = %d, want 405", post.Code)
	}
}
