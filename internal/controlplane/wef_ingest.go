package controlplane

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/wef"
)

// wefPollInterval is how often the WEF poller scans its drop directory (a WEC exports periodically).
const wefPollInterval = 30 * time.Second

// RunWEFIngest polls dir for Windows Event Forwarding XML files and persists each event into the
// external-log store (SIEM-4). A Windows Event Collector exports events as *.xml (the on-prem handoff);
// this ingests each new *.xml / *.xml.gz, renames it *.ingested (idempotent) and a bad file *.failed,
// reusing the shared directory-ingest helper. Runs on the LEADER only (leaderCtx) so a multi-instance
// deployment does not double-store.
func (s *Server) RunWEFIngest(ctx context.Context, dir string) error {
	tick := time.NewTicker(wefPollInterval)
	defer tick.Stop()
	s.scanWEFDir(ctx, dir) // ingest anything already present before the first tick
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			s.scanWEFDir(ctx, dir)
		}
	}
}

func (s *Server) scanWEFDir(ctx context.Context, dir string) {
	s.scanIngestDir(ctx, dir, "wef", isWEFFile, s.ingestWEFFile)
}

// ingestWEFFile reads, parses, and persists one WEF XML file.
func (s *Server) ingestWEFFile(ctx context.Context, path string) error {
	body, err := readBoundedFile(path, wef.MaxDelivery)
	if err != nil {
		s.WEFDropped.Add(1)
		return err
	}
	records, skipped, err := wef.Parse(body)
	if err != nil {
		s.WEFDropped.Add(1)
		return err
	}
	if skipped > 0 {
		s.WEFDropped.Add(int64(skipped))
	}
	for _, rec := range records {
		if err := s.InsertExternalLog(ctx, wefToExternalLog(rec)); err != nil {
			s.WEFDropped.Add(1)
			return fmt.Errorf("persisting event %q: %w", rec.EventID, err)
		}
		s.WEFIngested.Add(1)
	}
	return nil
}

// wefToExternalLog maps a Windows event onto the shared external-log shape, so Windows events are
// searchable by the SAME /logs query (vendor "microsoft") as CEF and CloudTrail.
func wefToExternalLog(r wef.Record) ExternalLog {
	// A compact human summary: provider/channel + a couple of common security-relevant EventData keys
	// when present (the full event stays in Raw for field-level hunting).
	msg := r.Provider + " [" + r.Channel + "] event " + r.EventID
	if u := firstNonEmpty(r.Data["TargetUserName"], r.Data["SubjectUserName"]); u != "" {
		msg += " user=" + u
	}
	if ip := r.Data["IpAddress"]; ip != "" && ip != "-" {
		msg += " ip=" + ip
	}
	host := r.Computer
	if host == "" {
		host = r.Data["IpAddress"] // fall back to a reported IP if the computer name is absent
	}
	return ExternalLog{
		ReceivedAt:  r.TimeCreated, // the event's own TimeCreated is the authoritative timestamp
		SourceHost:  host,
		Vendor:      "microsoft",
		Product:     "windows",
		SignatureID: r.EventID,
		Name:        r.Provider + "/" + r.EventID,
		Severity:    r.Level,
		Message:     msg,
		Raw:         r.Raw,
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// isWEFFile reports whether name is an un-processed WEF XML file.
func isWEFFile(name string) bool {
	if isProcessed(name) {
		return false
	}
	return strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".xml.gz")
}
