package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/lucianoengel/openshield/internal/clipboard"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// clipboardEvent builds a CONTENT-FREE clipboard-copy event (DLP-2a): how much was copied and which display
// server saw it, and nothing else. The copied bytes go to the sandboxed worker through the content store —
// never onto this Event (D10/D29). ClipboardSubject has no field that could hold them, so this is enforced
// by the contract rather than by care here.
func clipboardEvent(byteCount int, display string) *corev1.Event {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return &corev1.Event{
		// A random id per copy: two identical copies minutes apart are two events, and the id must not be
		// derived from the content (a content-derived id would leak a fingerprint of what was copied).
		EventId:     "clip-" + hex.EncodeToString(b[:]),
		ConnectorId: "clipboard",
		Kind:        corev1.EventKind_EVENT_KIND_CLIPBOARD_COPY,
		Purpose:     corev1.Purpose_PURPOSE_DLP,
		Target: &corev1.Event_Clipboard{Clipboard: &corev1.ClipboardSubject{
			ByteCount:     uint32(byteCount),
			DisplayServer: display,
		}},
	}
}

// clipboardSource is the clipboard exfil producer (DLP-2a). On each tick it polls the clipboard through the
// OS seam; when the content CHANGED it registers the bytes for the classify stage and emits the content-free
// event, so a sensitive copy is classified in the sandboxed worker and policy-gated like any other detection.
//
// It observes; it does not block a paste. Inline clipboard prevention is deliberately not in this increment.
func clipboardSource(ctx context.Context, r clipboard.Reader, store *clipboard.ContentStore,
	excl *clipboard.Exclusions, interval time.Duration, events chan<- *corev1.Event, log *slog.Logger) {
	// The polled backend has no source attribution, so exclusions cannot be applied here — the capability
	// report says so rather than implying a protection that is not in effect.
	w := &clipboard.Watcher{Reader: r, Exclusions: excl}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	// consecutiveErrors keeps a broken helper from logging once per interval forever while still surfacing
	// the first failures — the same reasoning as the exec gate's breaker, at a much lower stake.
	var consecutiveErrors int
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			readCtx, cancel := context.WithTimeout(ctx, interval)
			content, changed, err := w.Poll(readCtx)
			cancel()
			if err != nil {
				consecutiveErrors++
				if consecutiveErrors <= 3 {
					log.Warn("clipboard: read failed (monitoring continues; a persistent failure means the "+
						"helper or the display went away)", slog.Any("err", err),
						slog.Int("consecutive", consecutiveErrors))
				}
				continue
			}
			consecutiveErrors = 0
			if !changed {
				continue
			}
			ev := clipboardEvent(len(content), r.DisplayServer())
			// Register BEFORE emitting: the classify stage resolves content by event id, and emitting first
			// would race a fast pipeline to an empty classification.
			store.Put(ev.GetEventId(), content)
			select {
			case events <- ev:
				log.Info("clipboard: copy observed — classifying in the sandboxed worker",
					slog.Int("bytes", len(content)), slog.String("display", r.DisplayServer()))
			case <-ctx.Done():
				return
			}
		}
	}
}

// splitList parses a comma-separated operator list, ignoring blanks.
func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
