package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// TestFieldLevelSearch (SIEM field-level hunting, real PG): a search filtered by a parsed field
// key=value returns only the logs whose fields contain it, across sources; a non-matching value none.
//
// Mutation: if SearchExternalLogs ignored the field filter, the "only the matching row" assertion
// (exactly 2, both with the shared IP) FAILs.
func TestFieldLevelSearch(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	// A CloudTrail-shaped log and a WEF-shaped log SHARING a sourceIPAddress field value, plus an
	// unrelated one — the cross-source pivot the whole feature exists for.
	if err := srv.InsertExternalLog(ctx, controlplane.ExternalLog{
		Vendor: "aws", Product: "cloudtrail", Name: "ConsoleLogin",
		Fields: map[string]string{"sourceIPAddress": "203.0.113.7", "eventName": "ConsoleLogin"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.InsertExternalLog(ctx, controlplane.ExternalLog{
		Vendor: "microsoft", Product: "windows", SignatureID: "4624",
		Fields: map[string]string{"sourceIPAddress": "203.0.113.7", "TargetUserName": "alice"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := srv.InsertExternalLog(ctx, controlplane.ExternalLog{
		Vendor: "microsoft", Product: "windows", SignatureID: "4625",
		Fields: map[string]string{"sourceIPAddress": "10.0.0.9", "TargetUserName": "bob"},
	}); err != nil {
		t.Fatal(err)
	}

	// A field hunt on the shared IP returns BOTH sources' logs and not the unrelated one.
	got, err := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{FieldKey: "sourceIPAddress", FieldValue: "203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("field hunt on sourceIPAddress=203.0.113.7 returned %d rows, want 2 (CloudTrail + WEF)", len(got))
	}
	vendors := map[string]bool{}
	for _, r := range got {
		vendors[r.Vendor] = true
		if r.Fields["sourceIPAddress"] != "203.0.113.7" {
			t.Errorf("a returned row does not have the hunted field: %+v", r.Fields)
		}
	}
	if !vendors["aws"] || !vendors["microsoft"] {
		t.Fatalf("the field hunt did not span sources: %v", vendors)
	}

	// A field value nobody has → no rows.
	none, _ := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{FieldKey: "TargetUserName", FieldValue: "nobody"})
	if len(none) != 0 {
		t.Fatalf("a non-matching field value returned %d rows, want 0", len(none))
	}
}

// TestLogsEndpointFieldFilter (SIEM field-level hunting): GET /logs?field=key:value hunts by a parsed
// field; a malformed field param is a 400 (SEC-8).
//
// Mutation: if parseExternalLogFilter accepted a colon-less field, the 400 test FAILs.
func TestLogsEndpointFieldFilter(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	if err := srv.InsertExternalLog(ctx, controlplane.ExternalLog{
		Vendor: "microsoft", Product: "windows", SignatureID: "4624",
		Fields: map[string]string{"TargetUserName": "svc-backup"},
	}); err != nil {
		t.Fatal(err)
	}
	h := srv.OperatorReadHandler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/logs?field=TargetUserName:svc-backup", nil))
	if rec.Code != 200 {
		t.Fatalf("/logs field filter = %d, want 200", rec.Code)
	}
	var got []controlplane.ExternalLog
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Fields["TargetUserName"] != "svc-backup" {
		t.Fatalf("/logs?field=TargetUserName:svc-backup returned %+v, want the one matching log", got)
	}

	// Malformed field params → 400.
	for _, q := range []string{"/logs?field=nocolon", "/logs?field=:emptykey"} {
		bad := httptest.NewRecorder()
		h.ServeHTTP(bad, httptest.NewRequest("GET", q, nil))
		if bad.Code != 400 {
			t.Errorf("%s = %d, want 400", q, bad.Code)
		}
	}
}
