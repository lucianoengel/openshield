package core_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// unreachableLedger models the database being down. It is not a stub that
// "fails sometimes" — it is the specific condition the product will actually
// meet on a laptop that woke up on a train.
type unreachableLedger struct{ appends int }

func (l *unreachableLedger) Append(context.Context, *core.Entry) error {
	l.appends++
	return core.ErrLedgerUnavailable
}
func (l *unreachableLedger) Verify(context.Context) (core.VerifyResult, error) {
	return core.VerifyResult{}, core.ErrLedgerUnavailable
}
func (l *unreachableLedger) Close() error { return nil }

// recordingLedger captures what actually got written.
type recordingLedger struct{ entries []*core.Entry }

func (l *recordingLedger) Append(_ context.Context, e *core.Entry) error {
	cp := *e
	l.entries = append(l.entries, &cp)
	return nil
}
func (l *recordingLedger) Verify(context.Context) (core.VerifyResult, error) {
	return core.VerifyResult{Consistent: true}, nil
}
func (l *recordingLedger) Close() error { return nil }

type decidingStage struct{ d *corev1.Decision }

func (s decidingStage) Name() string { return "policy" }
func (s decidingStage) Run(context.Context, *core.State) (core.Outcome, error) {
	return core.Decided(s.d), nil
}

type hangingStage struct{}

func (hangingStage) Name() string { return "classifier" }
func (hangingStage) Run(ctx context.Context, _ *core.State) (core.Outcome, error) {
	<-ctx.Done()
	return core.Outcome{}, ctx.Err()
}

func dispatcherWith(t *testing.T, st core.Stage, l core.Ledger) *core.Dispatcher {
	t.Helper()
	var r core.Registry
	r.Register(st)
	d := core.NewDispatcher(&r, 100*time.Millisecond)
	d.OnOutcome = core.NewAuditSink(l).Record
	return d
}

// The whole point of the ledger. If an append failure can be swallowed, an
// unrecorded Decision is indistinguishable from an event that never happened —
// and the product's only honest claim (a trail of what it saw) is unbacked.
func TestUnreachableLedgerSurfacesAtTheCaller(t *testing.T) {
	l := &unreachableLedger{}
	d := dispatcherWith(t, decidingStage{&corev1.Decision{
		DecisionId: "d1", EventId: "e1", Action: corev1.Action_ACTION_ALLOW,
	}}, l)

	dec, err := d.Dispatch(context.Background(), &corev1.Event{EventId: "e1"})
	if err == nil {
		t.Fatal("append failure was swallowed — an unrecorded Decision would be " +
			"indistinguishable from an event that never occurred")
	}
	if !errors.Is(err, core.ErrNotRecorded) {
		t.Errorf("err = %v, want ErrNotRecorded so the caller can distinguish "+
			"'the pipeline failed' from 'the record failed'", err)
	}
	if l.appends != 1 {
		t.Errorf("appends = %d, want 1", l.appends)
	}
	// The Decision comes back too: a blocked process still needs an answer.
	// Returning nil here would turn an audit outage into a pipeline outage.
	if dec == nil {
		t.Error("Decision withheld because the append failed — the caller is " +
			"answering a blocked process and must still get a verdict")
	}
}

// A timeout is the outcome most likely to be lost, because nothing "went
// wrong" from the pipeline's point of view: it silently became an allow.
func TestTimeoutIsRecordedAndItsFailureSurfaces(t *testing.T) {
	rec := &recordingLedger{}
	d := dispatcherWith(t, hangingStage{}, rec)
	_, err := d.Dispatch(context.Background(), &corev1.Event{EventId: "e1"})
	if err == nil {
		t.Fatal("timeout produced no error")
	}
	if len(rec.entries) != 1 {
		t.Fatalf("entries = %d, want 1 — a timeout that is not audited is a "+
			"fail-open with no signal", len(rec.entries))
	}
	if got := rec.entries[0].OutcomeKind; got != "timeout" {
		t.Errorf("OutcomeKind = %q, want %q — a timeout recorded as an ordinary "+
			"outcome is indistinguishable from a clean allow", got, "timeout")
	}
	if rec.entries[0].OutcomeStage != "classifier" {
		t.Errorf("stage not attributed: %q", rec.entries[0].OutcomeStage)
	}

	// And when THAT append fails, it must surface too.
	d2 := dispatcherWith(t, hangingStage{}, &unreachableLedger{})
	_, err = d2.Dispatch(context.Background(), &corev1.Event{EventId: "e2"})
	if !errors.Is(err, core.ErrNotRecorded) {
		t.Errorf("err = %v, want ErrNotRecorded — an unrecorded timeout is the "+
			"quietest possible failure in the system", err)
	}
}

// A pipeline that produced no Decision at all must also leave a row. Silence
// would conflate "nothing matched" with "the pipeline fell off the end".
func TestNoDecisionIsStillRecorded(t *testing.T) {
	rec := &recordingLedger{}
	var r core.Registry
	d := core.NewDispatcher(&r, time.Second) // no stages at all
	d.OnOutcome = core.NewAuditSink(rec).Record

	if _, err := d.Dispatch(context.Background(), &corev1.Event{EventId: "e1"}); err == nil {
		t.Fatal("an Event that produced no Decision returned no error")
	}
	if len(rec.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rec.entries))
	}
	if rec.entries[0].Decision != nil {
		t.Error("a Decision was recorded where none was produced")
	}
}
