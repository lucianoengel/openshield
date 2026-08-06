package cli

import (
	"context"
	"fmt"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// THE REPLAY ANSWER, SEPARATED FROM THE WAY IT IS PRINTED (CONSOLE-10).
//
// `Replay` wrote prose to a writer and returned an exit code, which is exactly right for a CLI and
// unusable over HTTP. The console needs the same answer as a structure.
//
// EXTRACTED RATHER THAN REIMPLEMENTED, and here that is not a style preference. Replay's entire value is
// that it is the SAME answer wherever it is asked: an operator who gets "REPRODUCED" from the console and
// "DIVERGED" from `openshieldctl` has learned nothing except that the product cannot be trusted about the
// one thing it claims to be good at. Two implementations of a reproducibility check is a contradiction in
// terms.

// ReplayOutcome is the closed set of answers a replay can give.
type ReplayOutcome string

const (
	// ReplayReproduced: the policy re-evaluates this input to the decision the ledger recorded.
	ReplayReproduced ReplayOutcome = "reproduced"
	// ReplayDiverged: it does not. NOT necessarily a regression — see Caveat.
	ReplayDiverged ReplayOutcome = "diverged"
	// ReplayUnavailable: the comparison could not be made at all. Deliberately NOT folded into
	// "diverged": "the policy produced something different" and "there is no record of this decision"
	// call for different responses, and collapsing them lets a typo in an event id read as a policy
	// regression.
	ReplayUnavailable ReplayOutcome = "unavailable"
)

// ReplayResult is one replay, in a form both the CLI and the operator API can render.
type ReplayResult struct {
	Outcome ReplayOutcome `json:"outcome"`
	EventID string        `json:"event_id"`
	// Reason states why, in the operator's terms. Always set for diverged and unavailable.
	Reason string `json:"reason,omitempty"`

	// RecordedAction and ReplayedAction are the two verdicts being compared. Empty when the comparison
	// never happened.
	RecordedAction string  `json:"recorded_action,omitempty"`
	ReplayedAction string  `json:"replayed_action,omitempty"`
	Confidence     float64 `json:"confidence,omitempty"`

	// The policy that DECIDED and the policy that just RAN, named separately. A divergence explained by
	// "you are running a different policy" is not a regression and must not read like one.
	RecordedPolicyID      string `json:"recorded_policy_id,omitempty"`
	RecordedPolicyVersion string `json:"recorded_policy_version,omitempty"`
	ReplayedPolicyID      string `json:"replayed_policy_id,omitempty"`
	ReplayedPolicyVersion string `json:"replayed_policy_version,omitempty"`

	// Caveat is the limit on what this result establishes, and it is carried IN THE RESULT rather than
	// left to each renderer to remember. The ledger stores no content (D10/D29), so the replay read the
	// input as it is NOW: a divergence means the POLICY changed or the INPUT changed, and a reproduction
	// establishes only that the policy produces the recorded decision FROM THIS INPUT.
	//
	// A console that dropped this would turn a carefully-hedged answer into a confident one.
	Caveat string `json:"caveat"`
}

// Reproducible reports whether the recorded decision was reproduced. False for both diverged and
// unavailable, because a comparison that could not be made is not a positive result.
func (r ReplayResult) Reproducible() bool { return r.Outcome == ReplayReproduced }

const (
	caveatReproduced = "This establishes that the policy produces the recorded decision FROM THIS INPUT. " +
		"It does not establish that this input is what the original decision saw — the ledger keeps no content."
	caveatDiverged = "The ledger stores no content, so this replay read the input as it is NOW. A divergence " +
		"means the POLICY changed or the INPUT changed. Establish which before treating it as a regression."
)

// ReplayResultFor performs the comparison and returns it structurally. It is the single implementation;
// Replay renders it as prose and the operator API marshals it.
func ReplayResultFor(ctx context.Context, r Reader, d Dispatcher, e *corev1.Event) ReplayResult {
	res := ReplayResult{Outcome: ReplayUnavailable, EventID: e.GetEventId()}

	if e.GetEventId() == "" {
		res.Reason = "the supplied event carries no event id, so there is nothing to look up in the ledger"
		return res
	}
	entries, err := r.Entries(ctx)
	if err != nil {
		res.Reason = fmt.Sprintf("cannot read the ledger: %v", err)
		return res
	}

	var found []*core.Entry
	for _, ent := range entries {
		if ent.Decision.GetEventId() == e.GetEventId() {
			found = append(found, ent)
		}
	}
	switch len(found) {
	case 0:
		res.Reason = fmt.Sprintf("no ledger entry records a decision for event %q; this is not a "+
			"divergence — there is nothing to compare against", e.GetEventId())
		return res
	case 1:
	default:
		// Comparing against an arbitrary one would produce a confident answer about the wrong record.
		res.Reason = fmt.Sprintf("%d ledger entries record a decision for event %q; an event that "+
			"produced several decisions was either re-processed or is a bug, and either way the right "+
			"one to compare against is not this command's guess to make", len(found), e.GetEventId())
		return res
	}
	recorded := found[0].Decision
	res.RecordedAction = recorded.GetAction().String()
	res.RecordedPolicyID, res.RecordedPolicyVersion = recorded.GetPolicyId(), recorded.GetPolicyVersion()

	got, derr := d.Dispatch(ctx, e)
	if derr != nil {
		res.Reason = fmt.Sprintf("re-evaluating the event failed: %v", derr)
		return res
	}
	res.ReplayedAction = got.GetAction().String()
	res.ReplayedPolicyID, res.ReplayedPolicyVersion = got.GetPolicyId(), got.GetPolicyVersion()

	if eqErr := core.DecisionsEquivalent(recorded, got); eqErr != nil {
		res.Outcome, res.Reason, res.Caveat = ReplayDiverged, eqErr.Error(), caveatDiverged
		return res
	}
	res.Outcome, res.Confidence, res.Caveat = ReplayReproduced, recorded.GetConfidence(), caveatReproduced
	return res
}
