package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// TestRetentionReportRecordsAndQueries (SIEM-10, real PG): recorded retention purges are returned by
// RetentionReport (windowed, newest-first, filterable by target), including a ZERO-row purge (proving
// retention executed on schedule).
//
// Mutation: if RecordRetentionEvent no-ops, the report is empty → the assertions FAIL.
func TestRetentionReportRecordsAndQueries(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	cutoff := time.Unix(1_700_000_000, 0).UTC()

	srv.RecordRetentionEvent(ctx, "fleet_telemetry", 42, cutoff, "OPENSHIELD_FLEET_RETENTION=2160h")
	srv.RecordRetentionEvent(ctx, "notify_dedupe", 0, cutoff, "OPENSHIELD_NOTIFY_DEDUPE_RETENTION=24h") // zero-row, still recorded
	if srv.RetentionRecordFailures.Load() != 0 {
		t.Fatalf("record failures = %d, want 0", srv.RetentionRecordFailures.Load())
	}

	all, err := srv.RetentionReport(ctx, controlplane.RetentionReportFilter{Since: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("report returned %d events, want 2 (incl. the zero-row purge)", len(all))
	}

	// Filter by target.
	fleet, err := srv.RetentionReport(ctx, controlplane.RetentionReportFilter{Target: "fleet_telemetry"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fleet) != 1 || fleet[0].RowsAffected != 42 || fleet[0].Policy != "OPENSHIELD_FLEET_RETENTION=2160h" {
		t.Fatalf("fleet_telemetry report wrong: %+v", fleet)
	}
	if !fleet[0].Cutoff.Equal(cutoff) {
		t.Errorf("cutoff = %v, want %v", fleet[0].Cutoff, cutoff)
	}
	// The zero-row purge is queryable (compliance proof that retention ran).
	dd, _ := srv.RetentionReport(ctx, controlplane.RetentionReportFilter{Target: "notify_dedupe"})
	if len(dd) != 1 || dd[0].RowsAffected != 0 {
		t.Fatalf("notify_dedupe report should have one 0-row event, got %+v", dd)
	}
}

// TestComplianceRetentionEndpoint (SIEM-10): GET /compliance/retention returns the events; a malformed
// filter is a 400 (SEC-8).
//
// Mutation: if parseRetentionFilter ignored a bad since, the 400 test FAILs.
func TestComplianceRetentionEndpoint(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	srv.RecordRetentionEvent(ctx, "fleet_telemetry", 7, time.Now(), "OPENSHIELD_FLEET_RETENTION=2160h")

	h := srv.OperatorReadHandler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/compliance/retention?target=fleet_telemetry", nil))
	if rec.Code != 200 {
		t.Fatalf("/compliance/retention = %d, want 200", rec.Code)
	}
	var got []controlplane.RetentionEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if len(got) < 1 || got[0].Target != "fleet_telemetry" {
		t.Fatalf("report body = %+v, want a fleet_telemetry event", got)
	}

	bad := httptest.NewRecorder()
	h.ServeHTTP(bad, httptest.NewRequest("GET", "/compliance/retention?since=notatime", nil))
	if bad.Code != 400 {
		t.Fatalf("/compliance/retention?since=notatime = %d, want 400", bad.Code)
	}
}
