package controlplane

import (
	"context"
	"fmt"
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

// scanCloudTrailDir processes every un-suffixed *.json / *.json.gz file in dir once (via the shared
// scanIngestDir helper).
func (s *Server) scanCloudTrailDir(ctx context.Context, dir string) {
	s.scanIngestDir(ctx, dir, "cloudtrail", isCloudTrailFile, s.ingestCloudTrailFile)
}

// ingestCloudTrailFile reads, parses, and persists one CloudTrail delivery file.
func (s *Server) ingestCloudTrailFile(ctx context.Context, path string) error {
	body, err := readBoundedFile(path, cloudtrail.MaxDelivery)
	if err != nil {
		s.CloudTrailDropped.Add(1)
		return err
	}
	records, skipped, err := cloudtrail.Parse(body)
	if err != nil {
		s.CloudTrailDropped.Add(1)
		return err
	}
	if skipped > 0 {
		s.CloudTrailDropped.Add(int64(skipped))
	}
	for _, rec := range records {
		if err := s.InsertExternalLog(ctx, cloudTrailToExternalLog(rec)); err != nil {
			// A persist failure fails the WHOLE file (returned as an error → .failed), so it can be
			// re-dropped and re-ingested rather than partially applied and lost.
			s.CloudTrailDropped.Add(1)
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
	if isProcessed(name) {
		return false
	}
	return strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.gz")
}
