package controlplane_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

const wefFile = `<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID><Level>0</Level>
    <TimeCreated SystemTime="2026-07-22T10:15:30Z"/>
    <Computer>WIN-DC01.corp.local</Computer><Channel>Security</Channel>
  </System>
  <EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">10.0.0.5</Data></EventData>
</Event></Events>`

// TestWEFIngestPersistsAndIsIdempotent (SIEM-4, real PG): a WEF file dropped into the watched directory
// is parsed, persisted into external_logs (searchable as vendor "microsoft"), and renamed .ingested so
// a second scan does not re-insert.
//
// Mutation: if the scan did not rename after success, the second scan would re-ingest → "still one row"
// FAILs (this exercises the SHARED scanIngestDir helper, so it also guards the CloudTrail refactor).
func TestWEFIngestPersistsAndIsIdempotent(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)

	dir := t.TempDir()
	file := filepath.Join(dir, "sec.xml")
	if err := os.WriteFile(file, []byte(wefFile), 0o600); err != nil {
		t.Fatal(err)
	}

	srv.ScanWEFDirForTest(dir)

	logs, err := srv.SearchExternalLogs(context.Background(), controlplane.ExternalLogFilter{
		Vendor: "microsoft", Since: time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range logs {
		if r.Product == "windows" && r.SignatureID == "4624" && r.SourceHost == "WIN-DC01.corp.local" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("4624 rows = %d, want 1 (parsed+persisted from the dropped WEF file)", found)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("the ingested WEF file was not renamed — a restart would re-ingest it")
	}
	if _, err := os.Stat(file + ".ingested"); err != nil {
		t.Fatalf("expected %s.ingested: %v", file, err)
	}

	// A second scan must not re-ingest.
	srv.ScanWEFDirForTest(dir)
	logs2, _ := srv.SearchExternalLogs(context.Background(), controlplane.ExternalLogFilter{
		Vendor: "microsoft", Since: time.Unix(1_700_000_000, 0),
	})
	again := 0
	for _, r := range logs2 {
		if r.SignatureID == "4624" && r.SourceHost == "WIN-DC01.corp.local" {
			again++
		}
	}
	if again != 1 {
		t.Fatalf("after a second scan, 4624 rows = %d, want 1 — WEF ingest is not idempotent", again)
	}
}

// TestWEFIngestPoisonFileDoesNotBlock (SIEM-4): a malformed file is marked .failed and counted, and a
// valid file alongside still ingests.
func TestWEFIngestPoisonFileDoesNotBlock(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	dir := t.TempDir()

	poison := filepath.Join(dir, "bad.xml")
	if err := os.WriteFile(poison, []byte(`<Event><System><EventID>1`), 0o600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.xml")
	if err := os.WriteFile(good, []byte(wefFile), 0o600); err != nil {
		t.Fatal(err)
	}

	before := srv.WEFDropped.Load()
	srv.ScanWEFDirForTest(dir)

	if srv.WEFDropped.Load() <= before {
		t.Error("the poison WEF file was not counted as dropped")
	}
	if _, err := os.Stat(poison + ".failed"); err != nil {
		t.Errorf("poison file not marked .failed: %v", err)
	}
	if srv.WEFIngested.Load() < 1 {
		t.Error("the valid WEF file alongside the poison file did not ingest")
	}
}
