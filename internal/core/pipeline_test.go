package core_test

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// --- stages defined ONLY in this test package ---
//
// This matters. The architectural claim is that a capability can be added
// without editing the core or any other stage. A test using a stage the core
// already ships would prove nothing — it would confirm that a known stage runs.
// These types exist nowhere else.

type namedStage struct {
	name string
	fn   func(ctx context.Context, s *core.State) (core.Outcome, error)
}

func (n namedStage) Name() string { return n.name }
func (n namedStage) Run(ctx context.Context, s *core.State) (core.Outcome, error) {
	return n.fn(ctx, s)
}

func decideStage(name string, d *corev1.Decision) core.Stage {
	return namedStage{name, func(context.Context, *core.State) (core.Outcome, error) {
		return core.Decided(d), nil
	}}
}

func recordingStage(name string, log *[]string) core.Stage {
	return namedStage{name, func(context.Context, *core.State) (core.Outcome, error) {
		*log = append(*log, name)
		return core.Continue(), nil
	}}
}

func testEvent() *corev1.Event {
	return &corev1.Event{
		EventId: "evt-1", AgentId: "a1", ConnectorId: "fanotify",
		Sequence: 1, ObservedAt: timestamppb.Now(),
		Subject: &corev1.Subject{PseudonymousId: "s_1"},
		Purpose: corev1.Purpose_PURPOSE_DLP,
		Kind:    corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: "/tmp/a"}}},
	}
}

func testDecision() *corev1.Decision {
	return &corev1.Decision{
		DecisionId: "d1", EventId: "evt-1",
		Action: corev1.Action_ACTION_ALERT, Confidence: 0.9,
		Reason: "fixture", PolicyId: "p1", PolicyVersion: "1",
		DecidedAt: timestamppb.Now(),
	}
}

// TestStageAddedWithoutEditingAnything is the architectural claim in
// executable form: a stage defined entirely in this test package is registered
// and runs in order, and nothing in internal/core was modified to allow it.
func TestStageAddedWithoutEditingAnything(t *testing.T) {
	var log []string
	r := &core.Registry{}
	r.Register(recordingStage("classify", &log))
	r.Register(recordingStage("enrich", &log)) // the "new capability"
	r.Register(recordingStage("policy", &log))
	r.Register(decideStage("decide", testDecision()))

	d := core.NewDispatcher(r, time.Second)
	if _, err := d.Dispatch(context.Background(), testEvent()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if strings.Join(log, ",") != "classify,enrich,policy" {
		t.Errorf("stage order = %v, want classify,enrich,policy", log)
	}
}

// TestStageInterfaceExposesNoSiblingAccess asserts a stage cannot locate
// another stage. If the interface ever grows a registry or dispatcher handle,
// stages can start coupling to each other and the plugin claim dissolves.
func TestStageInterfaceExposesNoSiblingAccess(t *testing.T) {
	// Method set must be exactly Name() and Run().
	var s core.Stage = namedStage{"x", func(context.Context, *core.State) (core.Outcome, error) {
		return core.Continue(), nil
	}}
	_ = s

	// State is what a stage receives; it must not carry a way to reach the
	// pipeline. Checked by reflection so adding such a field fails here.
	// Context was added deliberately (T-030) and this list was updated on
	// purpose — that edit is the speed bump working, not an obstacle to route
	// around. The rule being enforced: State may carry DATA a stage reads, and
	// must never carry a HANDLE through which a stage could reach the
	// dispatcher, the registry or another stage.
	got := structFieldNames(core.State{})
	want := []string{"Classification", "Context", "Event"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("State fields = %v, want exactly %v — a stage must not be able to "+
			"reach the dispatcher, the registry or another stage", got, want)
	}

	// The distinction that matters: every State field must be inert data, not
	// something callable. A func or interface field would be a way out.
	rt := reflect.TypeOf(core.State{})
	for i := 0; i < rt.NumField(); i++ {
		switch rt.Field(i).Type.Kind() {
		case reflect.Func, reflect.Interface, reflect.Chan:
			t.Errorf("State.%s is %v — a stage could use it to reach outside itself",
				rt.Field(i).Name, rt.Field(i).Type.Kind())
		}
	}
}

func TestDispatchIsDeterministic(t *testing.T) {
	build := func() *core.Dispatcher {
		r := &core.Registry{}
		r.Register(namedStage{"policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
			d := testDecision()
			d.Reason = "path=" + s.Event.GetFilesystem().GetResolvedPath()
			return core.Decided(d), nil
		}})
		return core.NewDispatcher(r, time.Second)
	}
	a, err := build().Dispatch(context.Background(), testEvent())
	if err != nil {
		t.Fatal(err)
	}
	b, err := build().Dispatch(context.Background(), testEvent())
	if err != nil {
		t.Fatal(err)
	}
	if err := core.DecisionsEquivalent(a, b); err != nil {
		t.Errorf("same input produced different decisions: %v", err)
	}
}

func TestReentryIsRefused(t *testing.T) {
	r := &core.Registry{}
	var d *core.Dispatcher
	var inner error
	r.Register(namedStage{"reenter", func(ctx context.Context, s *core.State) (core.Outcome, error) {
		_, inner = d.Dispatch(ctx, s.Event) // must not recurse
		return core.Decided(testDecision()), nil
	}})
	d = core.NewDispatcher(r, time.Second)

	if _, err := d.Dispatch(context.Background(), testEvent()); err != nil {
		t.Fatalf("outer dispatch: %v", err)
	}
	if !errors.Is(inner, core.ErrReentry) {
		t.Errorf("inner dispatch error = %v, want ErrReentry", inner)
	}
}

// A failing stage must produce exactly one auditable outcome. Silence is the
// failure mode that makes a DLP tool worse than useless: an operator cannot
// distinguish "nothing sensitive happened" from "the classifier crashed".
func TestFailingStageIsAuditedExactlyOnce(t *testing.T) {
	r := &core.Registry{}
	r.Register(namedStage{"boom", func(context.Context, *core.State) (core.Outcome, error) {
		return core.Outcome{}, errors.New("classifier exploded")
	}})
	d := core.NewDispatcher(r, time.Second)

	var outcomes []core.Outcome
	d.OnOutcome = func(_ context.Context, _ *core.State, o core.Outcome) error {
		outcomes = append(outcomes, o)
		return nil
	}

	_, err := d.Dispatch(context.Background(), testEvent())
	if !errors.Is(err, core.ErrStageFailed) {
		t.Errorf("err = %v, want ErrStageFailed", err)
	}
	if len(outcomes) != 1 {
		t.Fatalf("audit records = %d, want exactly 1", len(outcomes))
	}
	if outcomes[0].Stage != "boom" {
		t.Errorf("outcome stage = %q, want %q — a failure must be attributable", outcomes[0].Stage, "boom")
	}
	if d.Metrics.Failed.Load() != 1 {
		t.Errorf("failed counter = %d, want 1", d.Metrics.Failed.Load())
	}
}

// A slow stage must not stall the pipeline, and the timeout must be LOUD.
// A quiet timeout is indistinguishable from a clean allow — which is exactly
// the fail-open bypass an attacker manufactures by making classification slow.
func TestSlowStageTimesOutLoudly(t *testing.T) {
	r := &core.Registry{}
	r.Register(namedStage{"slow", func(ctx context.Context, _ *core.State) (core.Outcome, error) {
		time.Sleep(2 * time.Second) // deliberately ignores ctx
		return core.Continue(), nil
	}})
	d := core.NewDispatcher(r, 50*time.Millisecond)

	var got []core.Outcome
	d.OnOutcome = func(_ context.Context, _ *core.State, o core.Outcome) error { got = append(got, o); return nil }

	start := time.Now()
	_, err := d.Dispatch(context.Background(), testEvent())
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("dispatch took %v — the deadline did not bound the wait", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
	if len(got) != 1 {
		t.Fatalf("outcomes = %d, want 1", len(got))
	}
	if got[0].Kind != core.OutcomeTimeout {
		t.Errorf("kind = %v, want timeout", got[0].Kind)
	}
	// The point of the test: severity, not mere presence.
	if got[0].Severity != core.SeverityHigh {
		t.Errorf("severity = %v, want high — a quiet timeout reads as a clean allow", got[0].Severity)
	}
}

// Timeouts must be counted separately from failures so a rising rate is its
// own signal (D17), not averaged into a general error count.
func TestTimeoutsCountedSeparatelyFromFailures(t *testing.T) {
	slow := &core.Registry{}
	slow.Register(namedStage{"slow", func(context.Context, *core.State) (core.Outcome, error) {
		time.Sleep(time.Second)
		return core.Continue(), nil
	}})
	d1 := core.NewDispatcher(slow, 20*time.Millisecond)
	_, _ = d1.Dispatch(context.Background(), testEvent())

	if d1.Metrics.TimedOut.Load() != 1 {
		t.Errorf("timeout counter = %d, want 1", d1.Metrics.TimedOut.Load())
	}
	if d1.Metrics.Failed.Load() != 0 {
		t.Errorf("failed counter = %d, want 0 — a timeout is not an ordinary failure",
			d1.Metrics.Failed.Load())
	}
}

// An Event that produces no Decision must not vanish. "No stage decided" and
// "allowed" are different facts and must not be conflated.
func TestNoDecisionIsStillReported(t *testing.T) {
	r := &core.Registry{}
	var log []string
	r.Register(recordingStage("noop", &log))
	d := core.NewDispatcher(r, time.Second)

	var got []core.Outcome
	d.OnOutcome = func(_ context.Context, _ *core.State, o core.Outcome) error { got = append(got, o); return nil }

	_, err := d.Dispatch(context.Background(), testEvent())
	if !errors.Is(err, core.ErrNoDecision) {
		t.Errorf("err = %v, want ErrNoDecision", err)
	}
	if len(got) != 1 {
		t.Errorf("outcomes = %d, want 1 — an undecided Event must still be auditable", len(got))
	}
}

// Replay must compare a field set that stays in step with the Decision message.
// If Decision grows a field that is neither compared nor deliberately excluded,
// replay silently covers less than it claims — so this fails instead.
func TestReplayFieldListCoversTheDecisionMessage(t *testing.T) {
	md := (&corev1.Decision{}).ProtoReflect().Descriptor()
	var actual []string
	for i := 0; i < md.Fields().Len(); i++ {
		actual = append(actual, string(md.Fields().Get(i).Name()))
	}
	accounted := map[string]bool{}
	for _, f := range core.ReplayComparedFields {
		accounted[f] = true
	}
	for _, f := range core.ReplayExcludedFields {
		accounted[f] = true
	}
	for _, f := range actual {
		if !accounted[f] {
			t.Errorf("Decision.%s is neither compared nor excluded by replay — "+
				"add it to ReplayComparedFields or ReplayExcludedFields deliberately", f)
		}
	}
}

func TestReplayReproducesRecordedDecision(t *testing.T) {
	build := func() *core.Dispatcher {
		r := &core.Registry{}
		r.Register(namedStage{"policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
			d := testDecision()
			d.Reason = "path=" + s.Event.GetFilesystem().GetResolvedPath()
			return core.Decided(d), nil
		}})
		return core.NewDispatcher(r, time.Second)
	}
	recorded, err := build().Dispatch(context.Background(), testEvent())
	if err != nil {
		t.Fatal(err)
	}
	// A fresh decision id and timestamp on replay must not break equivalence.
	recorded.DecisionId = "recorded-in-the-past"
	recorded.DecidedAt = timestamppb.New(time.Now().Add(-time.Hour))

	if err := core.Replay(context.Background(), build(), testEvent(), recorded); err != nil {
		t.Errorf("replay did not reproduce the recorded decision: %v", err)
	}
}

func TestReplayDetectsDivergence(t *testing.T) {
	a := testDecision()
	b := testDecision()
	b.Action = corev1.Action_ACTION_BLOCK
	if err := core.DecisionsEquivalent(a, b); err == nil {
		t.Error("replay comparison did not detect a differing action")
	}
}

func structFieldNames(v any) []string {
	var out []string
	rt := reflectTypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.IsExported() {
			out = append(out, f.Name)
		}
	}
	sort.Strings(out)
	return out
}

func reflectTypeOf(v any) reflect.Type { return reflect.TypeOf(v) }
