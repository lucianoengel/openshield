//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/fim"
)

// TestFimWatchMaskIncludesDelete asserts the real-time mask carries the deletion bits (no kernel needed) —
// keeps the mask honest against an accidental drop of the delete coverage.
func TestFimWatchMaskIncludesDelete(t *testing.T) {
	if fimWatchMask&unix.FAN_DELETE == 0 {
		t.Fatal("fimWatchMask must include FAN_DELETE (real-time deletion detection)")
	}
	if fimWatchMask&unix.FAN_MOVED_FROM == 0 {
		t.Fatal("fimWatchMask must include FAN_MOVED_FROM (a move out of the dir is a deletion)")
	}
}

// TestFimRealtimeDetectsDelete: a DELETION of a baselined file produces a real-time FILE_DELETED drift —
// the fanotify FAN_DELETE event triggers an immediate re-scan that reports the file gone, well within any
// realistic poll interval (fimWatchSource runs NO poll, so an event here is purely real-time). This also
// proves the unprivileged FID watch actually delivers FAN_DELETE on this kernel.
//
// Mutation (drop FAN_DELETE|FAN_MOVED_FROM from the mask): the delete never triggers a scan → no
// FILE_DELETED arrives in the real-time window → this test FAILs.
func TestFimRealtimeDetectsDelete(t *testing.T) {
	requireFanotify(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "critical.conf")
	if err := os.WriteFile(file, []byte("EVIDENCE"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, _, err := fim.BuildBaseline([]string{file}, fim.Options{})
	if err != nil {
		t.Fatal(err)
	}

	events := make(chan *corev1.Event, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fimWatchSource(ctx, baseline, []string{file}, fim.Options{}, 100*time.Millisecond, events, discardLogger())
	time.Sleep(200 * time.Millisecond) // let the watch arm

	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}

	got := drainFor(events, 3*time.Second)
	found := false
	for _, ev := range got {
		if ev.GetKind() == corev1.EventKind_EVENT_KIND_FILE_DELETED {
			found = true
		}
	}
	if !found {
		t.Fatalf("no real-time FILE_DELETED drift within 3s (got %d events) — the delete was not caught in real time", len(got))
	}
}
