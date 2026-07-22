package controlplane

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/notify"
)

type recordNotifier struct{ ids chan string }

func (r *recordNotifier) Notify(_ context.Context, n notify.Notification) error {
	r.ids <- n.ID
	return nil
}

func mustDeliver(t *testing.T, rn *recordNotifier) string {
	t.Helper()
	select {
	case id := <-rn.ids:
		return id
	case <-time.After(2 * time.Second):
		t.Fatal("expected a delivery, got none")
		return ""
	}
}

func mustNotDeliver(t *testing.T, rn *recordNotifier) {
	t.Helper()
	select {
	case id := <-rn.ids:
		t.Fatalf("expected NO further delivery, but delivered %q — the duplicate was not suppressed", id)
	case <-time.After(300 * time.Millisecond):
	}
}

// SIEM-12: the exact double-page scenario — an agent re-sends telemetry, the server re-detects and
// re-emits the SAME logical alert — must page EXACTLY ONCE. The id is derived deterministically from
// (kind, subject, agent, time-window), so a re-emit seconds later (same window) collapses to one
// delivery; a genuinely new occurrence in a later window pages again.
func TestEmitDedupesReDetectedAlert(t *testing.T) {
	rn := &recordNotifier{ids: make(chan string, 16)}
	s := &Server{notifyQ: make(chan notify.Notification, 256), notifyDedupe: newDedupeSet(4096)}
	s.SetNotifier(rn)

	ctx := context.Background()
	t0 := time.Unix(1_700_000_000, 0).UTC()
	peer := func(sub string, at time.Time) notify.Notification {
		return notify.Notification{Kind: notify.KindPeerAlert, Subject: sub, At: at}
	}

	// Re-detected 5s later — SAME 10-minute window ⇒ same id ⇒ exactly one delivery.
	s.emit(ctx, peer("alice", t0))
	s.emit(ctx, peer("alice", t0.Add(5*time.Second)))
	id1 := mustDeliver(t, rn)
	mustNotDeliver(t, rn)
	if got := s.NotifyDeduped.Load(); got != 1 {
		t.Errorf("NotifyDeduped = %d, want 1 (one re-detection suppressed)", got)
	}

	// A genuinely new occurrence in a LATER window pages again, with a different id.
	s.emit(ctx, peer("alice", t0.Add(20*time.Minute)))
	id2 := mustDeliver(t, rn)
	if id2 == id1 {
		t.Error("a later-window alert reused the earlier id — it would be wrongly suppressed")
	}

	// A different subject is a different alert ⇒ delivered.
	s.emit(ctx, peer("bob", t0))
	if id3 := mustDeliver(t, rn); id3 == id1 || id3 == id2 {
		t.Errorf("a different subject reused an id (%q)", id3)
	}
}

// The id is a pure function of the alert's identity + window — deterministic across re-emits, and
// distinct for a different subject or window.
func TestNotifyIDIsDeterministic(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0).UTC()
	base := notify.Notification{Kind: notify.KindPeerAlert, Subject: "alice", At: t0}
	if notifyID(base) != notifyID(base) {
		t.Fatal("notifyID is not deterministic for identical input")
	}
	// Same window, seconds apart → same id.
	if notifyID(base) != notifyID(notify.Notification{Kind: notify.KindPeerAlert, Subject: "alice", At: t0.Add(30 * time.Second)}) {
		t.Error("a re-detection within the window derived a different id")
	}
	// Different subject → different id.
	if notifyID(base) == notifyID(notify.Notification{Kind: notify.KindPeerAlert, Subject: "bob", At: t0}) {
		t.Error("different subjects collided to one id")
	}
	// Different window → different id.
	if notifyID(base) == notifyID(notify.Notification{Kind: notify.KindPeerAlert, Subject: "alice", At: t0.Add(20 * time.Minute)}) {
		t.Error("different windows collided to one id")
	}
}
