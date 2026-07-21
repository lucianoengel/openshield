// Package quarantine is a post-decision file enforcer (Phase 2).
//
// It carries out QUARANTINE_LOCAL by MOVING a flagged file into an owner-only
// quarantine directory. This is CONTAINMENT after detection, not PREVENTION: the
// file was already read (that is how it was classified), so quarantine contains
// it after the fact — it does not stop the access that triggered it. Defeatable
// by root (D16); the honest value is containing a careless insider's flagged
// file, audited.
package quarantine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/safeio"
)

// Mover moves a file from src to a destination directory. Behind an interface so
// the enforcement dispatch is testable without touching real files.
type Mover interface {
	Move(src, dstDir string) (string, error)
}

// Enforcer moves flagged files to a quarantine directory.
type Enforcer struct {
	Dir   string
	mover Mover
}

// New returns a quarantine enforcer writing to dir with the real filesystem mover.
func New(dir string) *Enforcer { return &Enforcer{Dir: dir, mover: fsMover{}} }

// WithMover is for tests.
func WithMover(dir string, m Mover) *Enforcer { return &Enforcer{Dir: dir, mover: m} }

func (e *Enforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_QUARANTINE_LOCAL}
}

// Enforce without a target cannot act — quarantine needs to know which file. It
// returns an error rather than silently doing nothing (a no-op enforcement is a
// containment that did not happen but looks like it did).
func (e *Enforcer) Enforce(_ context.Context, _ *corev1.Decision) error {
	return fmt.Errorf("quarantine: no target file supplied (use EnforceTarget)")
}

// EnforceTarget moves the target file into the quarantine directory.
func (e *Enforcer) EnforceTarget(_ context.Context, _ *corev1.Decision, target string) error {
	if target == "" {
		return fmt.Errorf("quarantine: empty target")
	}
	if _, err := e.mover.Move(target, e.Dir); err != nil {
		return fmt.Errorf("quarantine: moving %s: %w", target, err)
	}
	return nil
}

var (
	_ core.Enforcer         = (*Enforcer)(nil)
	_ core.TargetedEnforcer = (*Enforcer)(nil)
)

// fsMover moves files on the real filesystem into an owner-only quarantine dir.
type fsMover struct{}

func (fsMover) Move(src, dstDir string) (string, error) {
	// Refuse a swapped symlink / non-regular source (the classification→enforce
	// TOCTOU, D65): quarantining a symlink would move the link (or, via the
	// fallback, could copy an attacker-chosen file). A flagged file is a regular
	// file; anything else at enforce time is refused loudly.
	if err := safeio.RefuseNonRegular(src); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dstDir, filepath.Base(src))
	if err := os.Rename(src, dst); err != nil {
		// Rename fails across filesystems; fall back to copy+remove. Read WITHOUT
		// following a symlink at src: a swapped symlink must not make us copy an
		// attacker-chosen file into quarantine (D65). Rename itself does not follow
		// a symlink source; this closes the fallback path's follow.
		data, rerr := safeio.ReadRegularNoFollow(src)
		if rerr != nil {
			return "", rerr
		}
		if werr := os.WriteFile(dst, data, 0o600); werr != nil {
			return "", werr
		}
		_ = os.Remove(src)
	}
	return dst, nil
}
