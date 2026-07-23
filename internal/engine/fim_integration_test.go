package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/fim"
	"github.com/lucianoengel/openshield/internal/policy"
)

// tamperPolicy ALERTs on any file-integrity drift kind (modified/created/deleted).
func tamperPolicy(t *testing.T) *policy.Stage {
	t.Helper()
	pol, err := policy.New(context.Background(), "fim", "1", `package openshield
import rego.v1
tamper if { input.event.kind == "EVENT_KIND_FILE_MODIFIED" }
tamper if { input.event.kind == "EVENT_KIND_FILE_CREATED" }
tamper if { input.event.kind == "EVENT_KIND_FILE_DELETED" }
decision := {"action":"ALERT","reason":"file integrity drift","confidence":0.9} if { tamper }
decision := {"action":"ALLOW","reason":"ok","confidence":0.9} if { not tamper }`)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

// fimDriftEvent maps a fim.Drift to the pipeline event, mirroring the engine's fimSource.
func fimDriftEvent(d fim.Drift) *corev1.Event {
	var kind corev1.EventKind
	switch d.Change {
	case fim.Added:
		kind = corev1.EventKind_EVENT_KIND_FILE_CREATED
	case fim.Deleted:
		kind = corev1.EventKind_EVENT_KIND_FILE_DELETED
	default:
		kind = corev1.EventKind_EVENT_KIND_FILE_MODIFIED
	}
	return &corev1.Event{
		EventId: "fim-" + string(d.Change),
		Kind:    kind,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: d.Path}}},
	}
}

// TestFimDriftAlertsThroughEngine drives the REAL FIM scan and the REAL engine (real
// worker binary + a tamper policy): a timestomped MODIFY and a DELETE of a baselined
// critical file each produce an ALERT decision through the full pipeline. The DELETE
// specifically proves the classify-stage metadata-only fix — without it, the worker
// would error trying to open the missing file and no ALERT would be produced.
func TestFimDriftAlertsThroughEngine(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	modFile := filepath.Join(dir, "critical.conf")
	delFile := filepath.Join(dir, "audit.rules")
	if err := os.WriteFile(modFile, []byte("AAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(delFile, []byte("watch /etc"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(modFile)
	origMtime := fi.ModTime()

	baseline, _, err := fim.BuildBaseline([]string{modFile, delFile}, fim.Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Timestomp the modify (same size, restored mtime) and delete the other.
	if err := os.WriteFile(modFile, []byte("BBBB"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(modFile, origMtime, origMtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(delFile); err != nil {
		t.Fatal(err)
	}

	drifts, _, err := fim.Scan(baseline, []string{modFile, delFile}, fim.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) != 2 {
		t.Fatalf("expected 2 drifts (modified + deleted), got %v", drifts)
	}

	worker, err := privileged.StartWorker(ctx, buildWorker(t))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	eng := engine.New(worker, tamperPolicy(t), &recLedger{}, nil, 10*time.Second)

	for _, d := range drifts {
		dec, err := eng.Process(ctx, fimDriftEvent(d))
		if err != nil {
			t.Fatalf("process %s drift: %v", d.Change, err)
		}
		if dec.GetAction() != corev1.Action_ACTION_ALERT {
			t.Fatalf("%s drift on %s = %v, want ALERT", d.Change, filepath.Base(d.Path), dec.GetAction())
		}
	}
}

// TestFimCleanDoesNotAlert: an unchanged baseline yields no drift, so nothing enters the
// pipeline — no false-positive alert (proven at the scan boundary).
func TestFimCleanDoesNotAlert(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "stable.conf")
	if err := os.WriteFile(f, []byte("steady"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, _, _ := fim.BuildBaseline([]string{f}, fim.Options{})
	time.Sleep(10 * time.Millisecond)
	drifts, _, err := fim.Scan(baseline, []string{f}, fim.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) != 0 {
		t.Fatalf("clean baseline produced drift → would false-alert: %v", drifts)
	}
}
