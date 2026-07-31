package controlplane

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/jsonlog"
)

// GENERIC JSON-LINES INGEST (SIEM-15).
//
// CEF, CloudTrail and WEF each cover one vendor. JSON lines is what everything else emits — application
// logs, Kubernetes, GCP audit, Azure activity, every shipper's default output — so this is the format
// that turns "ingests three products" into "ingests an estate". It pairs with the cross-vendor vocabulary
// (SIEM-13), which is what makes a bag of dotted keys huntable alongside the rest.

// jsonLogPollInterval is how often the poller scans its drop directory. Shorter than the WEF poller's
// because a shipper writes continuously rather than exporting in batches.
const jsonLogPollInterval = 10 * time.Second

// maxJSONLogFile bounds one file. A drop directory is written by whatever an estate points at it, so an
// unbounded read is a denial of service reachable by anyone who can write a log.
const maxJSONLogFile = 64 << 20

// JSONLogIngested, JSONLogDropped and JSONLogSynthesizedTime are the counters for this source.
//
// THE THIRD ONE IS THE INTERESTING ONE. A JSON log has no agreed time field, so a source that names its
// timestamp something this parser does not know has EVERY event stamped with the moment it was ingested
// — the events are all there, all searchable, and all in the wrong place on the timeline. Nothing else
// about that source looks wrong, so a rising count here is the only way anyone finds out.
var (
	JSONLogIngested        atomic.Int64
	JSONLogDropped         atomic.Int64
	JSONLogSynthesizedTime atomic.Int64
)

// RunJSONLogIngest polls dir for newline-delimited JSON log files and persists each line into the
// external-log store. Same idempotency discipline as the other file pollers: a completed file is renamed
// *.ingested and a poison file *.failed, so a restart re-scans only fresh files. Leader-only, so a
// multi-instance deployment does not double-store.
func (s *Server) RunJSONLogIngest(ctx context.Context, dir, vendor string) error {
	tick := time.NewTicker(jsonLogPollInterval)
	defer tick.Stop()
	s.scanJSONLogDir(ctx, dir, vendor)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			s.scanJSONLogDir(ctx, dir, vendor)
		}
	}
}

func (s *Server) scanJSONLogDir(ctx context.Context, dir, vendor string) {
	s.scanIngestDir(ctx, dir, "jsonlog", isJSONLogFile, func(c context.Context, path string) error {
		return s.ingestJSONLogFile(c, path, vendor)
	})
}

// isJSONLogFile reports whether name is an un-processed JSON-lines file.
func isJSONLogFile(name string) bool {
	if isProcessed(name) {
		return false
	}
	for _, ext := range []string{".jsonl", ".ndjson", ".json", ".jsonl.gz", ".ndjson.gz", ".json.gz"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// ingestJSONLogFile reads, parses and persists one file.
//
// A file with SOME bad lines is still ingested: the good ones are stored and the bad ones counted. The
// alternative — failing the whole file — would let one truncated line at the end of a shipper's buffer
// discard everything before it, which is the shape of loss an estate notices only when it needs the
// events.
func (s *Server) ingestJSONLogFile(ctx context.Context, path, vendor string) error {
	body, err := readBoundedFile(path, maxJSONLogFile)
	if err != nil {
		JSONLogDropped.Add(1)
		return err
	}
	records, bad := jsonlog.ParseLines(string(body), s.now())
	if len(bad) > 0 {
		JSONLogDropped.Add(int64(len(bad)))
	}
	if len(records) == 0 {
		// Nothing usable. An error rather than a quiet success, so the file is marked .failed and an
		// operator sees a source that is sending something this parser cannot read at all — rather than
		// a directory that empties itself and stores nothing.
		return fmt.Errorf("no parseable JSON records (%d bad line(s))", len(bad))
	}
	for _, rec := range records {
		if err := s.InsertExternalLog(ctx, jsonLogToExternalLog(rec, vendor)); err != nil {
			JSONLogDropped.Add(1)
			return fmt.Errorf("persisting a record: %w", err)
		}
		JSONLogIngested.Add(1)
		if rec.TimeSynthetic {
			JSONLogSynthesizedTime.Add(1)
		}
	}
	return nil
}

// jsonLogToExternalLog maps a parsed record onto the shared external-log shape, so a JSON log is
// searchable by the SAME SearchExternalLogs as CEF, CloudTrail and WEF — and by the same canonical
// vocabulary.
//
// vendor comes from CONFIGURATION, not from the document: it is the operator's label for the source they
// pointed at this directory, and a vendor name taken from a field the log happened to carry would make
// one directory's contents split across facets nobody chose.
func jsonLogToExternalLog(rec jsonlog.Record, vendor string) ExternalLog {
	product := rec.Product
	if product == "" {
		product = "jsonlog"
	}
	if vendor == "" {
		vendor = "jsonlog"
	}
	msg := rec.Message
	if rec.Truncated {
		// Carried on the record an analyst reads, not only in a counter: this specific document is
		// partly represented, and a hunt over the fields it lost returns nothing that reads as absence.
		msg = "[fields truncated] " + msg
	}
	return ExternalLog{
		ReceivedAt:  rec.At,
		SourceHost:  rec.Host,
		Vendor:      vendor,
		Product:     product,
		SignatureID: rec.Fields["event.code"],
		Name:        rec.Fields["event.action"],
		Severity:    rec.Severity,
		Message:     msg,
		Raw:         rec.Raw,
		Fields:      rec.Fields,
	}
}
