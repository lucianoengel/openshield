//go:build linux

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/clipboard"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// mediateClipboard's RETURN VALUE decides whether the engine also starts the observe-only producer:
//
//	mediating := false
//	if ... { mediating = mediateClipboard(...) }
//	... later the polled reader starts only when !mediating
//
// So `false` on failure is what preserves clipboard visibility when mediation cannot be established. If it
// returned true after failing to open the display, the engine would skip the fallback AND have no mediator
// — no clipboard coverage at all, with nothing reporting a problem, because from the engine's point of
// view mediation is running.
//
// This is exercisable without X: opening a display that does not exist is the failure being asserted.
func TestMediationReportsUnavailableSoTheFallbackStillRuns(t *testing.T) {
	store := clipboard.NewContentStore(nil)
	excl := clipboard.NewExclusions()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	decide := func(*corev1.Event, string) bool { return false }

	for _, display := range []string{
		":99999",             // a display number nothing can be listening on
		"",                   // unset DISPLAY, which is what a headless service sees
		"not-a-display",      // malformed
		"/tmp/nonexistent:0", // a path-shaped value
	} {
		t.Run("display="+display, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			done := make(chan bool, 1)
			go func() { done <- mediateClipboard(ctx, display, store, excl, decide, log) }()

			select {
			case got := <-done:
				if got {
					t.Fatalf("mediateClipboard(%q) reported SUCCESS for a display it cannot open — the "+
						"engine would skip the observe-only fallback and run with no clipboard coverage "+
						"at all, while believing mediation is active", display)
				}
			case <-ctx.Done():
				t.Fatalf("mediateClipboard(%q) neither succeeded nor reported failure within the timeout; "+
					"the engine's startup would hang here", display)
			}
		})
	}
}
