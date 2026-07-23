package controlplane

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/cloudtrail"
)

// cloudTrailPollInterval is how often the ingest poller scans the drop directory. CloudTrail delivers
// in batches minutes apart, so a frequent poll is unnecessary; this keeps the scan cheap.
const cloudTrailPollInterval = 30 * time.Second

// RunCloudTrailIngest polls dir for CloudTrail deliveries and persists each event into the external-log
// store (SIEM-4). A CloudTrail delivery is JSON dropped into a directory (the common S3-synced pattern);
// this ingests each new *.json / *.json.gz, renames it *.ingested so a restart does not re-ingest
// (idempotent), and renames a bad file *.failed (counted, never retried forever or left to block the
// directory). Runs on the LEADER only (leaderCtx) so a multi-instance deployment does not double-store.
func (s *Server) RunCloudTrailIngest(ctx context.Context, dir string) error {
	tick := time.NewTicker(cloudTrailPollInterval)
	defer tick.Stop()
	s.scanCloudTrailDir(ctx, dir) // ingest anything already present before the first tick
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			s.scanCloudTrailDir(ctx, dir)
		}
	}
}

// scanCloudTrailDir processes every un-suffixed *.json / *.json.gz file in dir once.
func (s *Server) scanCloudTrailDir(ctx context.Context, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: cloudtrail dir %q unreadable: %v\n", dir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !isCloudTrailFile(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := s.ingestCloudTrailFile(ctx, path); err != nil {
			s.CloudTrailDropped.Add(1)
			fmt.Fprintf(os.Stderr, "openshield-server: cloudtrail file %q failed (%v) — marking .failed\n", e.Name(), err)
			_ = os.Rename(path, path+".failed") // do not retry a poison file forever
			continue
		}
		// Rename AFTER a successful full ingest so a crash mid-file re-processes it (at-least-once), and
		// a completed file is never re-ingested (the rename is the idempotency marker).
		if err := os.Rename(path, path+".ingested"); err != nil {
			fmt.Fprintf(os.Stderr, "openshield-server: cloudtrail file %q ingested but not renamed (%v) — skipping to avoid a re-ingest loop\n", e.Name(), err)
		}
	}
}

// ingestCloudTrailFile reads, parses, and persists one CloudTrail delivery file.
func (s *Server) ingestCloudTrailFile(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = io.LimitReader(f, cloudtrail.MaxDelivery+1)
	if strings.HasSuffix(path, ".gz") {
		gz, gerr := gzip.NewReader(r)
		if gerr != nil {
			return fmt.Errorf("gunzip: %w", gerr)
		}
		defer gz.Close()
		r = io.LimitReader(gz, cloudtrail.MaxDelivery+1)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	records, skipped, err := cloudtrail.Parse(body)
	if err != nil {
		return err
	}
	if skipped > 0 {
		s.CloudTrailDropped.Add(int64(skipped))
	}
	for _, rec := range records {
		if err := s.InsertExternalLog(ctx, cloudTrailToExternalLog(rec)); err != nil {
			// A persist failure fails the WHOLE file (returned as an error → .failed), so it can be
			// re-dropped and re-ingested rather than partially applied and lost.
			return fmt.Errorf("persisting record %q: %w", rec.EventName, err)
		}
		s.CloudTrailIngested.Add(1)
	}
	return nil
}

// cloudTrailToExternalLog maps a CloudTrail record onto the shared external-log shape, so cloud events
// are searchable by the SAME SearchExternalLogs (vendor "aws") as CEF and future sources.
func cloudTrailToExternalLog(r cloudtrail.Record) ExternalLog {
	return ExternalLog{
		ReceivedAt:  r.EventTime, // CloudTrail's own event time IS the authoritative audit timestamp
		SourceHost:  r.SourceIP,  // the actor's IP — a hunting pivot
		Vendor:      "aws",
		Product:     "cloudtrail",
		SignatureID: r.EventName,
		Name:        r.EventName,
		Severity:    r.ErrorCode, // empty on success; an error code is the failure signal
		Message:     r.EventSource + ":" + r.EventName + " by " + r.ActorARN + " in " + r.AWSRegion,
		Raw:         r.Raw,
	}
}

// isCloudTrailFile reports whether name is an un-processed CloudTrail delivery file. Already-processed
// files carry a .ingested/.failed suffix and are skipped, so a restart re-scans only fresh files.
func isCloudTrailFile(name string) bool {
	if strings.HasSuffix(name, ".ingested") || strings.HasSuffix(name, ".failed") {
		return false
	}
	return strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.gz")
}
