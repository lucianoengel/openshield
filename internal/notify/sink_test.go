package notify

import (
	"context"
	"errors"
	"testing"
)

// recordingNotifier records whether it was called and returns a fixed error (nil = success).
type recordingNotifier struct {
	called int
	err    error
}

func (r *recordingNotifier) Notify(context.Context, Notification) error {
	r.called++
	return r.err
}

// SIEM-8: a fanout attempts EVERY sink even when an earlier one fails — one broken sink must not
// suppress delivery to the healthy ones — and returns an aggregate error naming the failure.
func TestMultiDeliversToHealthySinkDespiteAFailure(t *testing.T) {
	bad := &recordingNotifier{err: errors.New("sink down")}
	good := &recordingNotifier{}
	m := &Multi{Sinks: []Notifier{bad, good}}

	err := m.Notify(context.Background(), Notification{})
	if err == nil {
		t.Fatal("Multi returned nil despite a failing sink — the caller would never log the failure")
	}
	if good.called != 1 {
		t.Errorf("the healthy sink was delivered to %d times, want 1 — a failing sink suppressed it", good.called)
	}
	if bad.called != 1 {
		t.Errorf("the failing sink was attempted %d times, want 1", bad.called)
	}
}

// The aggregate is Permanent only when EVERY failing sink is permanent; a mix that includes a
// transient failure must stay transient so an outer retry could still make progress.
func TestMultiAggregatePermanenceReflectsAllSinks(t *testing.T) {
	permBoth := &Multi{Sinks: []Notifier{
		&recordingNotifier{err: Permanent(errors.New("4xx a"))},
		&recordingNotifier{err: Permanent(errors.New("4xx b"))},
	}}
	if err := permBoth.Notify(context.Background(), Notification{}); !isPermanent(err) {
		t.Error("all-permanent aggregate is not permanent — an outer retry would waste attempts")
	}

	mixed := &Multi{Sinks: []Notifier{
		&recordingNotifier{err: Permanent(errors.New("4xx"))},
		&recordingNotifier{err: errors.New("503 transient")},
	}}
	if err := mixed.Notify(context.Background(), Notification{}); isPermanent(err) {
		t.Error("a mixed aggregate was marked permanent — the transient sink would never be retried")
	}
}

// All sinks succeeding returns nil; an empty fanout is a no-op success.
func TestMultiSuccessAndEmpty(t *testing.T) {
	m := &Multi{Sinks: []Notifier{&recordingNotifier{}, &recordingNotifier{}}}
	if err := m.Notify(context.Background(), Notification{}); err != nil {
		t.Errorf("all-success fanout returned %v, want nil", err)
	}
	if err := (&Multi{}).Notify(context.Background(), Notification{}); err != nil {
		t.Errorf("empty fanout returned %v, want nil (no-op)", err)
	}
}

// NewMulti collapses to the bare sink for one, Nop for none, a real fanout for many.
func TestNewMultiCollapses(t *testing.T) {
	only := &recordingNotifier{}
	if got := NewMulti(only); got != Notifier(only) {
		t.Error("NewMulti(single) should return the sink unwrapped")
	}
	if _, ok := NewMulti().(Nop); !ok {
		t.Error("NewMulti() should be a Nop")
	}
	if _, ok := NewMulti(&recordingNotifier{}, &recordingNotifier{}).(*Multi); !ok {
		t.Error("NewMulti(two) should be a *Multi fanout")
	}
}
