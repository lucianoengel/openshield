package queue_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/transport/queue"
)

// THE SPOOL CARRIES THREE PAYLOAD KINDS AND ONLY ONE OF THEM WAS TESTED.
//
// The existing fakeTransport records events and DISCARDS classifications and decisions — its
// PublishClassification and PublishDecision take `_` and return nil. So every test here exercised the event
// path, both other methods sat at 0%, and nothing could observe whether a decision that went into the spool
// came back out as a decision.
//
// That is the interesting question, because the spool is a byte-tagged format: `encode` prefixes one KIND
// BYTE and `Flush` switches on it. Get that mapping wrong in either direction and a decision replays as a
// classification — proto.Unmarshal will not object, since it is handed bytes that were a valid message of
// the other type and will often decode into *something*. The failure is silent and it lands in the audit
// trail, which is the one place D40's durable spool exists to protect.

// recorder captures every publish in order, tagged by kind, so replay ORDER and replay IDENTITY are both
// observable. Both matter and they fail differently.
type recorder struct {
	got         []string
	unreachable bool
	failWith    error
	closed      int
}

func (r *recorder) note(kind, id string) error {
	if r.failWith != nil {
		return r.failWith
	}
	if r.unreachable {
		return core.ErrUnreachable
	}
	r.got = append(r.got, kind+":"+id)
	return nil
}

func (r *recorder) PublishEvent(_ context.Context, e *corev1.Event) error {
	return r.note("event", e.GetEventId())
}

func (r *recorder) PublishClassification(_ context.Context, c *corev1.ClassificationSummary) error {
	return r.note("class", c.GetEventId())
}

func (r *recorder) PublishDecision(_ context.Context, d *corev1.Decision) error {
	return r.note("decision", d.GetEventId())
}

func (r *recorder) Close() error { r.closed++; return nil }

func (r *recorder) seen() string { return strings.Join(r.got, " ") }

// The spool is a directory, not a handle — it has no Close, which is the point of "the spool persists on
// disk for the next run".
func openSpool(t *testing.T, dir string) *queue.Queue {
	t.Helper()
	q, err := queue.Open(filepath.Join(dir, "spool"), 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func classification(id string) *corev1.ClassificationSummary {
	return &corev1.ClassificationSummary{EventId: id}
}

func decision(id string) *corev1.Decision { return &corev1.Decision{EventId: id} }

// Every kind must survive an outage, and come back AS ITSELF, in the order it was produced.
func TestAllThreeKindsSpoolAndReplayInOrderAsThemselves(t *testing.T) {
	r := &recorder{unreachable: true}
	tr := queue.Wrap(r, openSpool(t, t.TempDir()))
	ctx := context.Background()

	// Interleaved on purpose: a per-kind ordering that happened to work would pass a test that published
	// them in blocks, and the pipeline emits them interleaved (event -> classification -> decision, per file).
	if err := tr.PublishEvent(ctx, ev("e1")); err != nil {
		t.Fatalf("PublishEvent while offline: %v", err)
	}
	if err := tr.PublishClassification(ctx, classification("c1")); err != nil {
		t.Fatalf("PublishClassification while offline: %v", err)
	}
	if err := tr.PublishDecision(ctx, decision("d1")); err != nil {
		t.Fatalf("PublishDecision while offline: %v", err)
	}
	if err := tr.PublishEvent(ctx, ev("e2")); err != nil {
		t.Fatalf("PublishEvent while offline: %v", err)
	}
	if err := tr.PublishDecision(ctx, decision("d2")); err != nil {
		t.Fatalf("PublishDecision while offline: %v", err)
	}

	if r.seen() != "" {
		t.Fatalf("something reached the transport while it was unreachable: %q", r.seen())
	}

	r.unreachable = false
	n, err := tr.Flush(ctx)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if n != 5 {
		t.Fatalf("Flush delivered %d, want 5", n)
	}

	const want = "event:e1 class:c1 decision:d1 event:e2 decision:d2"
	if got := r.seen(); got != want {
		t.Fatalf("replay was\n  %q\nwant\n  %q\n"+
			"a mismatch in ORDER breaks the control plane's view of what happened when; a mismatch in KIND "+
			"means the spool's tag byte and Flush's switch disagree, and a decision has been replayed as "+
			"something else", got, want)
	}
}

// The type's own comment: "if anything is queued, a new payload goes BEHIND it rather than racing ahead on
// a recovered connection". The existing test proves that for events. It has to hold ACROSS kinds too — the
// spool is one ordered log, not three.
func TestARecoveredConnectionDoesNotLetALaterKindOvertakeTheSpool(t *testing.T) {
	r := &recorder{unreachable: true}
	tr := queue.Wrap(r, openSpool(t, t.TempDir()))
	ctx := context.Background()

	if err := tr.PublishEvent(ctx, ev("first")); err != nil { // spooled: transport is down
		t.Fatal(err)
	}

	// The connection comes back. A decision published now MUST NOT be sent directly, because that would put
	// it ahead of the event it followed.
	r.unreachable = false
	if err := tr.PublishDecision(ctx, decision("second")); err != nil {
		t.Fatal(err)
	}
	if got := r.seen(); got != "" {
		t.Fatalf("a decision overtook the spooled event and was sent directly: %q", got)
	}

	if _, err := tr.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := r.seen(), "event:first decision:second"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A CONNECTIVITY failure is the spool's job. Anything else is the caller's, and must NOT be reported as
// durably held — "your decision is safely queued" is a lie if it was rejected for being malformed or
// unauthorised, and the caller has been told there is nothing to retry.
func TestANonConnectivityErrorIsReturnedAndNotSpooled(t *testing.T) {
	boom := errors.New("malformed payload rejected")
	q := openSpool(t, t.TempDir())
	r := &recorder{failWith: boom}
	tr := queue.Wrap(r, q)
	ctx := context.Background()

	for name, publish := range map[string]func() error{
		"event":          func() error { return tr.PublishEvent(ctx, ev("e")) },
		"classification": func() error { return tr.PublishClassification(ctx, classification("c")) },
		"decision":       func() error { return tr.PublishDecision(ctx, decision("d")) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := publish(); !errors.Is(err, boom) {
				t.Fatalf("got %v, want the transport's own error", err)
			}
			if n := q.Len(); n != 0 {
				t.Fatalf("the spool holds %d records after a non-connectivity failure — the caller was told "+
					"to stop retrying AND the payload was kept, so it will be delivered by a later Flush "+
					"with nobody expecting it", n)
			}
		})
	}
}

func TestCloseClosesTheInnerTransport(t *testing.T) {
	r := &recorder{}
	tr := queue.Wrap(r, openSpool(t, t.TempDir()))
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if r.closed != 1 {
		t.Fatalf("inner transport closed %d times, want 1 — a wrapper that swallows Close leaks the "+
			"connection it wraps", r.closed)
	}
}
