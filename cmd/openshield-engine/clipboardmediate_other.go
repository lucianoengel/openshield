//go:build !linux

package main

import (
	"context"
	"log/slog"

	"github.com/lucianoengel/openshield/internal/clipboard"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// mediateClipboard is unavailable off Linux: clipboard mediation is built on the X11 selection protocol.
// Returning false keeps the caller on the observe-only path rather than pretending to enforce.
func mediateClipboard(context.Context, string, *clipboard.ContentStore, *clipboard.Exclusions,
	func(*corev1.Event, string) bool, chan<- *corev1.Event, *slog.Logger) bool {
	return false
}
