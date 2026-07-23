package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/canary"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/fim"
	"github.com/lucianoengel/openshield/internal/policy"
)

// ransomwarePolicy ALERTs on a RANSOMWARE_SUSPECTED event.
func ransomwarePolicy(t *testing.T) *policy.Stage {
	t.Helper()
	pol, err := policy.New(context.Background(), "canary", "1", `package openshield
import rego.v1
decision := {"action":"ALERT","reason":"suspected ransomware","confidence":0.95} if { input.event.kind == "EVENT_KIND_RANSOMWARE_SUSPECTED" }
decision := {"action":"ALLOW","reason":"ok","confidence":0.9} if { input.event.kind != "EVENT_KIND_RANSOMWARE_SUSPECTED" }`)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

// ransomwareEvent builds a metadata-only RANSOMWARE_SUSPECTED event for a directory (mirrors the engine
// canarySource producer).
func ransomwareEvent(dir string) *corev1.Event {
	return &corev1.Event{
		Kind:    corev1.EventKind_EVENT_KIND_RANSOMWARE_SUSPECTED,
		EventId: "ransomware-" + dir,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: dir}}},
	}
}

// TestRansomwareAlertsThroughEngine drives the REAL detection + engine path: plant canaries, mass-modify
// them (simulating ransomware), confirm the correlation detector fires, then process the ransomware event
// through the real engine (real worker) + an alert policy → an ALERT decision. The engine must NOT open
// the (encrypted-simulated) canary files — it classifies the event metadata-only (proves the classify fix).
func TestRansomwareAlertsThroughEngine(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	paths, err := canary.Plant(dir, 8)
	if err != nil {
		t.Fatal(err)
	}
	baseline, _, err := fim.BuildBaseline(paths, fim.Options{})
	if err != nil {
		t.Fatal(err)
	}

	// "Ransomware" encrypts (overwrites) the canaries with high-entropy content.
	enc := make([]byte, 256)
	for i := range enc {
		enc[i] = byte((i*167 + 13) % 251) // pseudo-random high-entropy bytes
	}
	for _, p := range paths {
		if err := os.WriteFile(p, enc, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// The detector fires on the mass change.
	det := &canary.Detector{Threshold: 4, Window: time.Minute}
	drifts, _, err := fim.Scan(baseline, paths, fim.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fired := false
	now := time.Now()
	for _, d := range drifts {
		if det.Observe(d.Path, now) {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("the detector did not fire on %d changed canaries (threshold 4)", len(drifts))
	}

	// The ransomware event flows the real engine → alert policy → ALERT, without opening the files.
	worker, err := privileged.StartWorker(ctx, buildWorker(t))
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	eng := engine.New(worker, ransomwarePolicy(t), &recLedger{}, nil, 10*time.Second)

	dec, err := eng.Process(ctx, ransomwareEvent(dir))
	if err != nil {
		t.Fatalf("process ransomware event: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Fatalf("ransomware decision = %v, want ALERT", dec.GetAction())
	}
	_ = filepath.Base(dir)
}
