package core

import (
	"context"
	"fmt"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Replay re-runs a recorded Event through a pipeline configuration and reports
// whether the resulting Decision matches the recorded one.
//
// Replay is what makes the audit trail an investigation tool rather than a log.
// "Every decision should be explainable" is unfounded if a recorded decision
// cannot be reproduced.
func Replay(ctx context.Context, d *Dispatcher, e *corev1.Event, recorded *corev1.Decision) error {
	got, err := d.Dispatch(ctx, e)
	if err != nil {
		return fmt.Errorf("replay dispatch: %w", err)
	}
	return DecisionsEquivalent(recorded, got)
}

// DecisionsEquivalent compares two Decisions on an EXPLICIT field list.
//
// The list is deliberately explicit rather than "everything except a denylist".
// With a denylist, a newly added non-deterministic field would be silently
// excluded and replay would quietly weaken. With an allowlist, adding a field
// that ought to be compared means this function — and the test that pins the
// field set — has to be edited on purpose.
//
// Excluded by design, because they legitimately differ between runs:
//   - decision_id (fresh per evaluation)
//   - decided_at  (wall clock)
//   - event_id    (carried through, compared separately by the caller if wanted)
func DecisionsEquivalent(want, got *corev1.Decision) error {
	if want == nil || got == nil {
		return fmt.Errorf("replay: nil decision (want=%v got=%v)", want != nil, got != nil)
	}
	if want.GetAction() != got.GetAction() {
		return fmt.Errorf("replay: action %v != %v", want.GetAction(), got.GetAction())
	}
	if want.GetConfidence() != got.GetConfidence() {
		return fmt.Errorf("replay: confidence %v != %v", want.GetConfidence(), got.GetConfidence())
	}
	if want.GetReason() != got.GetReason() {
		return fmt.Errorf("replay: reason %q != %q", want.GetReason(), got.GetReason())
	}
	if want.GetPolicyId() != got.GetPolicyId() {
		return fmt.Errorf("replay: policy_id %q != %q", want.GetPolicyId(), got.GetPolicyId())
	}
	if want.GetPolicyVersion() != got.GetPolicyVersion() {
		return fmt.Errorf("replay: policy_version %q != %q", want.GetPolicyVersion(), got.GetPolicyVersion())
	}
	// Compared, not excluded: a Decision evaluated against a different context
	// version may legitimately differ, so replay must be told which context to
	// reproduce against rather than silently accepting either.
	if want.GetContextVersion() != got.GetContextVersion() {
		return fmt.Errorf("replay: context_version %q != %q",
			want.GetContextVersion(), got.GetContextVersion())
	}
	return nil
}

// ReplayComparedFields is the compared set, exported so a test can assert that
// the Decision message has not grown a field which is neither compared nor
// deliberately excluded. Without that assertion, a new field would default to
// "not compared" and replay would silently cover less than it claims.
var ReplayComparedFields = []string{
	"action", "confidence", "reason", "policy_id", "policy_version", "context_version",
}

// ReplayExcludedFields are non-deterministic by nature.
var ReplayExcludedFields = []string{
	"decision_id", "decided_at", "event_id",
}
