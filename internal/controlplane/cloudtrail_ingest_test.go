package controlplane_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

const ctDelivery = `{"Records":[
  {"eventTime":"2026-07-22T10:15:30Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin",
   "awsRegion":"us-east-1","sourceIPAddress":"203.0.113.7","errorCode":"",
   "recipientAccountId":"123456789012","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"}}
]}`

// TestCloudTrailIngestPersistsAndIsIdempotent (SIEM-4, real PG): a CloudTrail file dropped into the
// watched directory is parsed, persisted into external_logs (searchable as vendor "aws"), and renamed
// .ingested so a second scan does not re-insert it.
//
// Mutation: if the scan did not rename after success, the second scan would re-ingest → the "still one
// row" assertion FAILs.
func TestCloudTrailIngestPersistsAndIsIdempotent(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)

	dir := t.TempDir()
	file := filepath.Join(dir, "ct.json")
	if err := os.WriteFile(file, []byte(ctDelivery), 0o600); err != nil {
		t.Fatal(err)
	}

	srv.ScanCloudTrailDirForTest(dir)

	// The event is persisted and searchable as an AWS external log.
	got, err := srv.SearchExternalLogs(context.Background(), controlplane.ExternalLogFilter{
		Vendor: "aws", Since: time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, r := range got {
		if r.Product == "cloudtrail" && r.Name == "ConsoleLogin" && r.SourceHost == "203.0.113.7" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("ConsoleLogin rows = %d, want 1 (parsed+persisted from the dropped file)", found)
	}
	// The file was renamed to mark it processed.
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("the ingested file was not renamed — a restart would re-ingest it")
	}
	if _, err := os.Stat(file + ".ingested"); err != nil {
		t.Fatalf("expected %s.ingested to exist: %v", file, err)
	}

	// A second scan must NOT re-ingest (the .ingested file is skipped).
	srv.ScanCloudTrailDirForTest(dir)
	got2, _ := srv.SearchExternalLogs(context.Background(), controlplane.ExternalLogFilter{
		Vendor: "aws", Since: time.Unix(1_700_000_000, 0),
	})
	again := 0
	for _, r := range got2 {
		if r.Product == "cloudtrail" && r.Name == "ConsoleLogin" && r.SourceHost == "203.0.113.7" {
			again++
		}
	}
	if again != 1 {
		t.Fatalf("after a second scan, ConsoleLogin rows = %d, want 1 — the ingest is not idempotent", again)
	}
}

// TestCloudTrailIngestPoisonFileDoesNotBlock (SIEM-4): a malformed file is marked .failed and counted,
// and a valid file dropped alongside still ingests.
func TestCloudTrailIngestPoisonFileDoesNotBlock(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	dir := t.TempDir()

	poison := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(poison, []byte(`{"not":"a cloudtrail delivery"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(ctDelivery), 0o600); err != nil {
		t.Fatal(err)
	}

	before := srv.CloudTrailDropped.Load()
	srv.ScanCloudTrailDirForTest(dir)

	if srv.CloudTrailDropped.Load() <= before {
		t.Error("the poison file was not counted as dropped")
	}
	if _, err := os.Stat(poison + ".failed"); err != nil {
		t.Errorf("poison file was not marked .failed: %v", err)
	}
	if srv.CloudTrailIngested.Load() < 1 {
		t.Error("the valid file alongside the poison file did not ingest")
	}
}
