package cli_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/cli"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// THE REPLAY ANSWER AS A STRUCTURE (CONSOLE-10).
//
// Extracted from the prose renderer so a second caller cannot reimplement the comparison. Replay's whole
// value is being the SAME answer wherever it is asked: an operator who gets "REPRODUCED" from one surface
// and "DIVERGED" from another has learned only that the product cannot be trusted about the one thing it
// claims to be good at.

type stubReader struct {
	entries []*core.Entry
	err     error
}

func (s stubReader) Entries(context.Context) ([]*core.Entry, error) { return s.entries, s.err }

// Verify satisfies cli.Reader. Replay never calls it — the reproducibility question and the
// tamper-evidence question are separate, and a replay that quietly verified the chain would conflate
// "the policy still decides this" with "the ledger was not edited".
func (s stubReader) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, errors.New("stubReader: Verify is not part of a replay")
}

type stubDispatcher struct {
	dec *corev1.Decision
	err error
}

func (s stubDispatcher) Dispatch(context.Context, *corev1.Event) (*corev1.Decision, error) {
	return s.dec, s.err
}

func decision(eventID string, action corev1.Action, policyID, version string) *corev1.Decision {
	return &corev1.Decision{
		EventId: eventID, Action: action, PolicyId: policyID, PolicyVersion: version, Confidence: 0.9,
	}
}

// TestUnavailableIsNeverReportedAsDivergence.
//
// The distinction is the point of the closed outcome set: "the policy produced something different" and
// "there is no record of this decision" call for different responses, and collapsing them lets a typo in
// an event id read as a policy regression.
//
// Mutation: return ReplayDiverged for the no-entry case → FAILS.
func TestUnavailableIsNeverReportedAsDivergence(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    cli.Reader
		d    cli.Dispatcher
		ev   *corev1.Event
		want string
	}{
		{"no event id", stubReader{}, stubDispatcher{}, &corev1.Event{}, "no event id"},
		{"ledger unreadable", stubReader{err: errors.New("boom")}, stubDispatcher{},
			&corev1.Event{EventId: "e1"}, "cannot read the ledger"},
		{"no entry for this event", stubReader{}, stubDispatcher{},
			&corev1.Event{EventId: "e1"}, "not a divergence"},
		{"two entries for one event",
			stubReader{entries: []*core.Entry{
				{Decision: decision("e1", corev1.Action_ACTION_ALERT, "p", "1")},
				{Decision: decision("e1", corev1.Action_ACTION_ALERT, "p", "1")},
			}}, stubDispatcher{}, &corev1.Event{EventId: "e1"}, "not this command's guess"},
		{"re-evaluation failed",
			stubReader{entries: []*core.Entry{{Decision: decision("e1", corev1.Action_ACTION_ALERT, "p", "1")}}},
			stubDispatcher{err: errors.New("policy exploded")},
			&corev1.Event{EventId: "e1"}, "re-evaluating the event failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cli.ReplayResultFor(context.Background(), tc.r, tc.d, tc.ev)
			if got.Outcome != cli.ReplayUnavailable {
				t.Fatalf("outcome = %q, want unavailable — reporting this as a divergence would send an "+
					"operator hunting a policy regression that did not happen", got.Outcome)
			}
			if got.Reproducible() {
				t.Error("an unavailable comparison reported itself as reproducible")
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Errorf("reason %q does not explain the cause (want %q)", got.Reason, tc.want)
			}
		})
	}
}

// TestAReproductionAndADivergenceBothCarryTheirCaveat.
//
// The caveat lives IN THE RESULT rather than in each renderer, because a surface that forgot it would
// turn a carefully-hedged answer into a confident one. The ledger stores no content, so the replay read
// the input as it is NOW.
//
// Mutation: leave Caveat empty on either branch → FAILS.
func TestAReproductionAndADivergenceBothCarryTheirCaveat(t *testing.T) {
	recorded := decision("e1", corev1.Action_ACTION_ALERT, "openshield.default", "1")
	r := stubReader{entries: []*core.Entry{{Decision: recorded}}}

	same := cli.ReplayResultFor(context.Background(), r,
		stubDispatcher{dec: decision("e1", corev1.Action_ACTION_ALERT, "openshield.default", "1")},
		&corev1.Event{EventId: "e1"})
	if same.Outcome != cli.ReplayReproduced || !same.Reproducible() {
		t.Fatalf("outcome = %q, want reproduced", same.Outcome)
	}
	if !strings.Contains(same.Caveat, "does not establish") {
		t.Errorf("a reproduction carries no caveat (%q) — without it the console reports that the "+
			"original decision was verified, which this cannot show", same.Caveat)
	}

	diff := cli.ReplayResultFor(context.Background(), r,
		stubDispatcher{dec: decision("e1", corev1.Action_ACTION_BLOCK, "openshield.default", "2")},
		&corev1.Event{EventId: "e1"})
	if diff.Outcome != cli.ReplayDiverged || diff.Reproducible() {
		t.Fatalf("outcome = %q, want diverged", diff.Outcome)
	}
	if !strings.Contains(diff.Caveat, "POLICY changed or the INPUT changed") {
		t.Errorf("a divergence carries no caveat (%q) — an operator who reverts a policy over a file "+
			"somebody edited has been misled by a technically accurate report", diff.Caveat)
	}
}

// TestTheTwoPolicyIdentitiesAreReportedSeparately — a divergence explained by "you are running a
// different policy" is not a regression and must not read like one.
func TestTheTwoPolicyIdentitiesAreReportedSeparately(t *testing.T) {
	r := stubReader{entries: []*core.Entry{
		{Decision: decision("e1", corev1.Action_ACTION_ALERT, "openshield.default", "1")}}}
	got := cli.ReplayResultFor(context.Background(), r,
		stubDispatcher{dec: decision("e1", corev1.Action_ACTION_BLOCK, "openshield.composite", "7")},
		&corev1.Event{EventId: "e1"})

	if got.RecordedPolicyID == got.ReplayedPolicyID {
		t.Fatalf("both policy ids read %q — the surface cannot distinguish a regression from a "+
			"different policy", got.RecordedPolicyID)
	}
	if got.RecordedPolicyVersion != "1" || got.ReplayedPolicyVersion != "7" {
		t.Errorf("versions = %q/%q, want 1/7", got.RecordedPolicyVersion, got.ReplayedPolicyVersion)
	}
	if got.RecordedAction == got.ReplayedAction {
		t.Errorf("both actions read %q; the two verdicts being compared must be visible",
			got.RecordedAction)
	}
}

// TestTheResultSerializesWithItsCaveat — whatever renders this next must receive the limit along with
// the answer, so the caveat cannot be dropped by omission.
func TestTheResultSerializesWithItsCaveat(t *testing.T) {
	r := stubReader{entries: []*core.Entry{
		{Decision: decision("e1", corev1.Action_ACTION_ALERT, "p", "1")}}}
	got := cli.ReplayResultFor(context.Background(), r,
		stubDispatcher{dec: decision("e1", corev1.Action_ACTION_ALERT, "p", "1")},
		&corev1.Event{EventId: "e1"})

	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"caveat"`) {
		t.Errorf("the serialized result omits the caveat: %s", b)
	}
	if !strings.Contains(string(b), `"outcome":"reproduced"`) {
		t.Errorf("the outcome is not on the wire: %s", b)
	}
}
