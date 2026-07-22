package prefilter_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/prefilter"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// cleanWorker classifies everything as no-hit, so a regular-file read completes.
type cleanWorker struct{}

func (cleanWorker) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	return &corev1.ClassifyResponse{RequestId: req.GetRequestId(), EventId: req.GetEventId()}, nil
}

// SEC-7: the prefilter's prefix read uses the no-follow safe opener — a flagged path swapped
// for a SYMLINK is refused, closing the TOCTOU an attacker could use to redirect the read
// onto an arbitrary file (mirrors the enforcer safeio discipline, D65).
func TestPrefilterRefusesSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	ctx := context.Background()
	pol, err := policy.NewDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// No worker is needed: the read is refused BEFORE classification, so a nil classifier
	// is never called. (DecidePartial opens the file first.)
	d := prefilter.NewDecider(nil, pol, 0, time.Second, nil)

	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("cpf 111.444.777-35"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "flagged")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	// The prefilter is asked to classify the SYMLINK path — it must refuse to follow it.
	_, err = d.DecidePartial(ctx, watchdog.PermissionEvent{Path: link})
	if err == nil {
		t.Fatal("the prefilter followed a symlink target — SEC-7 TOCTOU open")
	}
}

// A regular file is still read normally (the fix does not break the happy path).
func TestPrefilterReadsRegularFile(t *testing.T) {
	ctx := context.Background()
	pol, err := policy.NewDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A nil classifier would be called for a regular file, so guard: this test only asserts
	// the OPEN succeeds (a regular file is not refused). Use a fake classifier returning no
	// hits so DecidePartial completes.
	d := prefilter.NewDecider(cleanWorker{}, pol, 0, time.Second, nil)
	dir := t.TempDir()
	f := filepath.Join(dir, "regular")
	if err := os.WriteFile(f, []byte("nothing sensitive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DecidePartial(ctx, watchdog.PermissionEvent{Path: f}); err != nil {
		t.Errorf("a regular file was refused: %v", err)
	}
}
