package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The one core change peer-UEBA needs (D26): a Context resolver hook. Nil leaves
// Context nil (unchanged); a resolver flows a Context to the stages.
func TestResolveContextHook(t *testing.T) {
	// Nil resolver → Context nil (Phase-1 observe-only unchanged).
	var seenNil *core.Context
	var r1 core.Registry
	r1.Register(stageFuncCore("s", func(_ context.Context, st *core.State) (core.Outcome, error) {
		seenNil = st.Context
		return core.Decided(&corev1.Decision{DecisionId: "d", EventId: st.Event.GetEventId(), Action: corev1.Action_ACTION_ALLOW}), nil
	}))
	d1 := core.NewDispatcher(&r1, time.Second)
	if _, err := d1.Dispatch(context.Background(), &corev1.Event{EventId: "e1"}); err != nil {
		t.Fatal(err)
	}
	if seenNil != nil {
		t.Error("Context was non-nil with no resolver — the default must be unchanged behaviour")
	}

	// A resolver → the stage sees the resolved Context.
	var seen *core.Context
	var r2 core.Registry
	r2.Register(stageFuncCore("s", func(_ context.Context, st *core.State) (core.Outcome, error) {
		seen = st.Context
		return core.Decided(&corev1.Decision{DecisionId: "d", EventId: st.Event.GetEventId(), Action: corev1.Action_ACTION_ALLOW}), nil
	}))
	d2 := core.NewDispatcher(&r2, time.Second)
	d2.ResolveContext = func(*corev1.Event) *core.Context {
		return &core.Context{Version: "v1", RiskScore: 0.9, HasRiskScore: true}
	}
	if _, err := d2.Dispatch(context.Background(), &corev1.Event{EventId: "e2"}); err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen.Version != "v1" || seen.RiskScore != 0.9 {
		t.Errorf("resolved Context did not reach the stage: %+v", seen)
	}
}

type stageFnCore struct {
	name string
	fn   func(context.Context, *core.State) (core.Outcome, error)
}

func (s stageFnCore) Name() string { return s.name }
func (s stageFnCore) Run(ctx context.Context, st *core.State) (core.Outcome, error) {
	return s.fn(ctx, st)
}
func stageFuncCore(n string, fn func(context.Context, *core.State) (core.Outcome, error)) core.Stage {
	return stageFnCore{n, fn}
}
