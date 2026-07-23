package controlplane

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// scanIngestDir processes every un-suffixed target file in dir once (SIEM-4 external-file ingest,
// shared by the CloudTrail and WEF pollers): for each file matching isTarget it calls ingestOne, then
// renames it *.ingested on success and *.failed on error — the rename is the idempotency marker, so a
// restart re-scans only fresh files and a completed file is never re-ingested. Rename-AFTER-success
// gives at-least-once (a crash mid-file re-processes) rather than at-most-once. Per-format drop counting
// lives in ingestOne; `label` names the format in log lines.
func (s *Server) scanIngestDir(ctx context.Context, dir, label string, isTarget func(string) bool, ingestOne func(context.Context, string) error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: %s dir %q unreadable: %v\n", label, dir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !isTarget(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := ingestOne(ctx, path); err != nil {
			fmt.Fprintf(os.Stderr, "openshield-server: %s file %q failed (%v) — marking .failed\n", label, e.Name(), err)
			_ = os.Rename(path, path+".failed") // do not retry a poison file forever
			continue
		}
		if err := os.Rename(path, path+".ingested"); err != nil {
			fmt.Fprintf(os.Stderr, "openshield-server: %s file %q ingested but not renamed (%v) — skipping to avoid a re-ingest loop\n", label, e.Name(), err)
		}
	}
}

// isProcessed reports whether name already carries a processed-marker suffix, so a re-scan skips it.
func isProcessed(name string) bool {
	return strings.HasSuffix(name, ".ingested") || strings.HasSuffix(name, ".failed")
}

// openMaybeGzip opens path, bounding the read to max+1 bytes (so an over-limit file is detected, not
// truncated into a parseable-but-wrong record), transparently gunzipping a .gz. The caller closes
// nothing extra — the returned bytes are read fully here.
func readBoundedFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = io.LimitReader(f, max+1)
	if strings.HasSuffix(path, ".gz") {
		gz, gerr := gzip.NewReader(r)
		if gerr != nil {
			return nil, fmt.Errorf("gunzip: %w", gerr)
		}
		defer gz.Close()
		r = io.LimitReader(gz, max+1)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return body, nil
}
