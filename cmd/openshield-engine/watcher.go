package main

import (
	"context"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// fileWatcher is the file-observation producer the engine consumes. It is satisfied
// by the Linux fanotify connector in unprivileged NOTIFY mode (D52) and by the
// portable poll-based connector on other operating systems. openFileWatcher selects
// the implementation at BUILD TIME (watcher_linux.go / watcher_other.go), so this
// file and main.go hold no OS-specific code and the Linux observe path stays
// fanotify, byte-for-byte — the portable watcher is not compiled on Linux, and
// fanotify is not compiled elsewhere (ADR-11/PLAT-7).
type fileWatcher interface {
	Next(ctx context.Context) (*corev1.Event, error)
	Close() error
}
