//go:build linux

package main

import (
	"context"
	"log/slog"
	"strings"

	"github.com/lucianoengel/openshield/internal/clipboard"
	"github.com/lucianoengel/openshield/internal/clipboard/x11"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// mediateClipboard runs X11 clipboard MEDIATION (DLP-2a increment 2): the engine owns the CLIPBOARD
// selection and decides each paste, rather than watching copies after the fact.
//
// The shape mirrors enterprise endpoint DLP — decide per (content, source, destination) at transfer time —
// implemented through X11's native interposition point instead of by injecting into applications.
//
// It returns false when mediation is unavailable, so the caller can fall back to the polled producer.
func mediateClipboard(ctx context.Context, display string, store *clipboard.ContentStore,
	excl *clipboard.Exclusions, decide func(*corev1.Event, string) bool,
	events chan<- *corev1.Event, log *slog.Logger) bool {
	m, err := x11.Open(display)
	if err != nil {
		log.Warn("engine: clipboard MEDIATION unavailable — falling back to observe-only capture",
			slog.Any("err", err))
		return false
	}
	m.MaxBytes = clipboard.MaxBytes
	m.Logf = func(format string, a ...any) { log.Info(strings.TrimSpace(format), slog.Any("args", a)) }
	m.Excluded = excl.Excluded

	// OnCopy: classify through the real pipeline and report whether the content is sensitive. Only
	// sensitive content is mediated — taking ownership for every copy would be needless interference with
	// a desktop that is mostly copying non-sensitive text.
	m.OnCopy = func(c x11.Copy) bool {
		ev := clipboardEvent(len(c.Content), clipboard.DisplayX11)
		store.Put(ev.GetEventId(), c.Content)
		select {
		case events <- ev:
		case <-ctx.Done():
			return false
		}
		return decide(ev, c.SourceExe)
	}

	// Decide: the per-paste enforcement point. The destination is what makes this a real DLP decision
	// rather than an alert — the same content can go to an editor and not to a browser.
	m.Decide = func(t x11.Transfer) x11.Decision {
		log.Warn("clipboard: paste requested for mediated content",
			slog.String("source", t.SourceExe), slog.Int("source_pid", t.SourcePID),
			slog.String("destination", t.DestExe), slog.Int("dest_pid", t.DestPID),
			slog.Int("bytes", t.Bytes))
		// Increment 2 ships the MECHANISM with a conservative default: mediated (i.e. sensitive) content is
		// refused. Destination-conditional policy — "allow into an editor, refuse into a browser" — is the
		// obvious next step and needs a policy input for the destination, which is deliberately NOT
		// invented here.
		return x11.Deny
	}

	caps := clipboard.X11MediationCapabilities()
	log.Warn("engine: clipboard MEDIATION ACTIVE — pastes of sensitive content are DECIDED, not just observed",
		slog.String("capabilities", caps.Summary()), slog.Any("limits", caps.Limits))
	go func() {
		if err := m.Run(ctx); err != nil {
			log.Error("clipboard mediation stopped", slog.Any("err", err))
		}
	}()
	return true
}
