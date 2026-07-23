//go:build !linux

package main

import (
	"context"
	"log/slog"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/fim"
)

// fimWatchSource is a no-op off Linux (fanotify is Linux-only); FIM still runs via the periodic poll.
func fimWatchSource(_ context.Context, _ *fim.Manifest, _ []string, _ fim.Options, _ time.Duration, _ chan<- *corev1.Event, log *slog.Logger) {
	log.Info("fim: real-time watch is Linux-only — running poll-only")
}
