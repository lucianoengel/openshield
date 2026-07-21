package queue_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/transport/queue"
)

// fakeTransport records what it received and can be toggled unreachable.
type fakeTransport struct {
	reachable bool
	events    []string // event ids, in the order received
}

func (f *fakeTransport) PublishEvent(_ context.Context, e *corev1.Event) error {
	if !f.reachable {
		return core.ErrUnreachable
	}
	f.events = append(f.events, e.GetEventId())
	return nil
}
func (f *fakeTransport) PublishClassification(_ context.Context, _ *corev1.ClassificationSummary) error {
	if !f.reachable {
		return core.ErrUnreachable
	}
	return nil
}
func (f *fakeTransport) PublishDecision(_ context.Context, _ *corev1.Decision) error {
	if !f.reachable {
		return core.ErrUnreachable
	}
	return nil
}
func (f *fakeTransport) Close() error { return nil }

func ev(id string) *corev1.Event { return &corev1.Event{EventId: id} }

func openQ(t *testing.T, dir string, max int, onOverflow func(uint64)) *queue.Queue {
	t.Helper()
	q, err := queue.Open(dir, max, onOverflow)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// Offline → publish several → online → Flush: all delivered, FIFO order.
func TestOfflineThenFlushInOrder(t *testing.T) {
	dir := t.TempDir()
	inner := &fakeTransport{reachable: false}
	qt := queue.Wrap(inner, openQ(t, dir, 100, nil))

	ids := []string{"e0", "e1", "e2", "e3"}
	for _, id := range ids {
		if err := qt.PublishEvent(context.Background(), ev(id)); err != nil {
			t.Fatalf("publish %s while offline should succeed (durably held): %v", id, err)
		}
	}
	if len(inner.events) != 0 {
		t.Fatalf("delivered %v while offline — nothing should reach an unreachable transport", inner.events)
	}

	inner.reachable = true
	n, err := qt.Flush(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != len(ids) {
		t.Errorf("flushed %d, want %d", n, len(ids))
	}
	if got := inner.events; !equal(got, ids) {
		t.Errorf("delivered %v, want %v in FIFO order", got, ids)
	}
}

// The queue survives a restart (reopen the same directory).
func TestSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	inner := &fakeTransport{reachable: false}
	qt := queue.Wrap(inner, openQ(t, dir, 100, nil))
	for _, id := range []string{"a", "b", "c"} {
		_ = qt.PublishEvent(context.Background(), ev(id))
	}

	// "Restart": a brand-new queue + transport over the same spool dir.
	inner2 := &fakeTransport{reachable: true}
	qt2 := queue.Wrap(inner2, openQ(t, dir, 100, nil))
	n, err := qt2.Flush(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || !equal(inner2.events, []string{"a", "b", "c"}) {
		t.Errorf("after restart delivered %v (n=%d), want a,b,c — the spool did not survive", inner2.events, n)
	}
}

// Overflow drops the OLDEST, fires the callback, and keeps the newest.
func TestOverflowDropsOldestLoudly(t *testing.T) {
	dir := t.TempDir()
	var dropped []uint64
	inner := &fakeTransport{reachable: false}
	qt := queue.Wrap(inner, openQ(t, dir, 3, func(seq uint64) { dropped = append(dropped, seq) }))

	for _, id := range []string{"e0", "e1", "e2", "e3", "e4"} { // 2 past the ceiling of 3
		if err := qt.PublishEvent(context.Background(), ev(id)); err != nil {
			t.Fatal(err)
		}
	}
	if len(dropped) != 2 {
		t.Errorf("overflow callback fired %d times, want 2 — a drop must be loud", len(dropped))
	}
	// The three newest (e2,e3,e4) survive; e0,e1 were dropped.
	inner.reachable = true
	if _, err := qt.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !equal(inner.events, []string{"e2", "e3", "e4"}) {
		t.Errorf("survivors = %v, want e2,e3,e4 — overflow must drop OLDEST and keep newest", inner.events)
	}
}

// Online with an empty queue publishes directly, touching no disk.
func TestOnlineEmptyGoesDirect(t *testing.T) {
	dir := t.TempDir()
	inner := &fakeTransport{reachable: true}
	qt := queue.Wrap(inner, openQ(t, dir, 100, nil))

	if err := qt.PublishEvent(context.Background(), ev("e0")); err != nil {
		t.Fatal(err)
	}
	if !equal(inner.events, []string{"e0"}) {
		t.Errorf("online publish did not go direct: %v", inner.events)
	}
	// No .msg file should have been written.
	files, _ := filepath.Glob(filepath.Join(dir, "*.msg"))
	if len(files) != 0 {
		t.Errorf("a file was written for a direct online publish: %v", files)
	}
}

// Once anything is queued, later payloads queue behind it even if the inner
// transport recovers mid-stream — FIFO must not be broken by a payload overtaking
// the queue.
func TestQueuedPayloadsAreNotOvertaken(t *testing.T) {
	dir := t.TempDir()
	inner := &fakeTransport{reachable: false}
	qt := queue.Wrap(inner, openQ(t, dir, 100, nil))

	_ = qt.PublishEvent(context.Background(), ev("first"))  // queued (offline)
	inner.reachable = true                                  // control plane recovers...
	_ = qt.PublishEvent(context.Background(), ev("second")) // ...but this must NOT overtake "first"

	if len(inner.events) != 0 {
		t.Fatalf("a payload overtook the queue: %v — FIFO order was broken", inner.events)
	}
	if _, err := qt.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !equal(inner.events, []string{"first", "second"}) {
		t.Errorf("delivered %v, want first,second", inner.events)
	}
}

// Flush stops on ErrUnreachable and keeps the undelivered tail.
func TestFlushStopsWhenUnreachableAgain(t *testing.T) {
	dir := t.TempDir()
	inner := &flakyTransport{}
	qt := queue.Wrap(inner, openQ(t, dir, 100, nil))
	for _, id := range []string{"e0", "e1", "e2"} {
		inner.reachable = false
		_ = qt.PublishEvent(context.Background(), ev(id))
	}
	// Deliver only the first, then go unreachable again.
	inner.reachable = true
	inner.failAfter = 1
	n, err := qt.Flush(context.Background())
	if !errors.Is(err, core.ErrUnreachable) {
		t.Fatalf("Flush err = %v, want ErrUnreachable", err)
	}
	if n != 1 {
		t.Errorf("delivered %d before the outage, want 1", n)
	}
	// The undelivered tail must remain; a full Flush now completes it in order.
	inner.failAfter = -1
	n2, err := qt.Flush(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 2 || !equal(inner.events, []string{"e0", "e1", "e2"}) {
		t.Errorf("after recovery delivered %v (n=%d), want e0,e1,e2 — the tail was lost or reordered", inner.events, n2)
	}
}

// flakyTransport delivers up to failAfter events then returns ErrUnreachable.
type flakyTransport struct {
	reachable bool
	failAfter int // -1 = never fail; N = fail after N deliveries this Flush
	events    []string
	delivered int
}

func (f *flakyTransport) PublishEvent(_ context.Context, e *corev1.Event) error {
	if !f.reachable {
		return core.ErrUnreachable
	}
	if f.failAfter >= 0 && f.delivered >= f.failAfter {
		return core.ErrUnreachable
	}
	f.events = append(f.events, e.GetEventId())
	f.delivered++
	return nil
}
func (f *flakyTransport) PublishClassification(context.Context, *corev1.ClassificationSummary) error {
	return nil
}
func (f *flakyTransport) PublishDecision(context.Context, *corev1.Decision) error { return nil }
func (f *flakyTransport) Close() error                                            { return nil }

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
