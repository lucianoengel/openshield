package cli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/cli"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// DECISION REPLAY (the reproducible half of the platform's claim).
//
// The four outcomes are distinct on purpose and each has its own exit code, because the command's
// intended use is a pipeline gate on a policy change. Collapsing "no such decision" into "diverged"
// would let a typo in an event id fail a gate as if the policy had regressed.

type replayReader struct {
	entries []*core.Entry
	err     error
}

func (r replayReader) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}
func (r replayReader) Entries(context.Context) ([]*core.Entry, error) { return r.entries, r.err }

// fixedDispatcher returns a decision regardless of input — the replay under test is about COMPARISON,
// and a real pipeline here would make each case depend on classifier behaviour instead.
type fixedDispatcher struct {
	dec *corev1.Decision
	err error
}

func (d fixedDispatcher) Dispatch(context.Context, *corev1.Event) (*corev1.Decision, error) {
	return d.dec, d.err
}

func decisionFor(eventID string, action corev1.Action, reason string) *corev1.Decision {
	return &corev1.Decision{
		EventId: eventID, Action: action, Reason: reason,
		Confidence: 0.9, PolicyId: "default", PolicyVersion: "1",
	}
}

func replay(t *testing.T, entries []*core.Entry, got *corev1.Decision, eventID string) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	code := cli.Replay(context.Background(), &buf, replayReader{entries: entries},
		fixedDispatcher{dec: got}, &corev1.Event{EventId: eventID})
	return code, buf.String()
}

func entryFor(d *corev1.Decision) *core.Entry { return &core.Entry{Decision: d} }

// TestAnUnchangedPolicyReproduces.
func TestAnUnchangedPolicyReproduces(t *testing.T) {
	rec := decisionFor("e1", corev1.Action_ACTION_ALERT, "checksum-backed PII")
	// A DISTINCT object with the same values, not the same pointer: comparing a decision with itself
	// would pass against a comparison that does nothing at all.
	got := decisionFor("e1", corev1.Action_ACTION_ALERT, "checksum-backed PII")

	code, out := replay(t, []*core.Entry{entryFor(rec)}, got, "e1")
	if code != cli.ExitOK {
		t.Errorf("exit %d, want %d — an unchanged policy did not reproduce its own decision:\n%s",
			code, cli.ExitOK, out)
	}
	if !strings.Contains(out, "REPRODUCED") {
		t.Errorf("the report does not say REPRODUCED:\n%s", out)
	}
	// AND IT STATES WHAT IT DID NOT ESTABLISH. A bare "REPRODUCED" invites the reading that the input
	// was verified too, when the ledger holds no content and the input came from the operator.
	if !strings.Contains(out, "does not establish") {
		t.Errorf("a successful replay does not state its limit — that the input is not known to be "+
			"what the original decision saw:\n%s", out)
	}
}

// TestAChangedDecisionDiverges, with the field named and both causes given.
func TestAChangedDecisionDiverges(t *testing.T) {
	rec := decisionFor("e1", corev1.Action_ACTION_ALERT, "checksum-backed PII")
	got := decisionFor("e1", corev1.Action_ACTION_ALLOW, "no alert condition met")

	code, out := replay(t, []*core.Entry{entryFor(rec)}, got, "e1")
	if code != cli.ExitInconsistent {
		t.Errorf("exit %d, want %d — a divergence that exits zero is a gate that never fails:\n%s",
			code, cli.ExitInconsistent, out)
	}
	if !strings.Contains(out, "DIVERGED") || !strings.Contains(out, "action") {
		t.Errorf("the report does not say DIVERGED and name the differing field:\n%s", out)
	}
	// THE AMBIGUITY MUST BE STATED. An operator who reverts a policy over a file somebody edited has
	// been misled by a report that was technically accurate.
	for _, want := range []string{"POLICY changed", "INPUT changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the divergence report does not name %q as a possible cause:\n%s", want, out)
		}
	}
}

// TestAnUnrecordedEventIsNotADivergence.
func TestAnUnrecordedEventIsNotADivergence(t *testing.T) {
	other := decisionFor("someone-else", corev1.Action_ACTION_ALERT, "x")
	code, out := replay(t, []*core.Entry{entryFor(other)},
		decisionFor("e1", corev1.Action_ACTION_ALERT, "x"), "e1")
	if code == cli.ExitInconsistent {
		t.Errorf("an event with NO recorded decision was reported as a divergence. A typo in an event "+
			"id would then fail a policy gate as if the policy had regressed:\n%s", out)
	}
	if code != cli.ExitUnavailable {
		t.Errorf("exit %d, want %d:\n%s", code, cli.ExitUnavailable, out)
	}
	if !strings.Contains(out, "not a divergence") {
		t.Errorf("the report does not distinguish itself from a divergence:\n%s", out)
	}
}

// TestAnAmbiguousEventIdIsRefused: comparing against an arbitrary one produces a confident answer
// about the wrong record, which is worse than no answer.
func TestAnAmbiguousEventIdIsRefused(t *testing.T) {
	a := decisionFor("e1", corev1.Action_ACTION_ALERT, "first")
	b := decisionFor("e1", corev1.Action_ACTION_ALLOW, "second")
	code, out := replay(t, []*core.Entry{entryFor(a), entryFor(b)},
		decisionFor("e1", corev1.Action_ACTION_ALERT, "first"), "e1")
	if code != cli.ExitUnavailable {
		t.Errorf("exit %d, want %d — two entries matched and one of them was compared against "+
			"anyway:\n%s", code, cli.ExitUnavailable, out)
	}
	if !strings.Contains(out, "2 ledger entries") {
		t.Errorf("the refusal does not say how many entries matched:\n%s", out)
	}
}

// TestAFailedReEvaluationIsUnavailable: "the pipeline broke" is not "the policy decided differently".
func TestAFailedReEvaluationIsUnavailable(t *testing.T) {
	var buf bytes.Buffer
	rec := decisionFor("e1", corev1.Action_ACTION_ALERT, "x")
	code := cli.Replay(context.Background(), &buf,
		replayReader{entries: []*core.Entry{entryFor(rec)}},
		fixedDispatcher{err: fmt.Errorf("worker unreachable")},
		&corev1.Event{EventId: "e1"})
	if code == cli.ExitInconsistent {
		t.Errorf("a failed re-evaluation was reported as a DIVERGENCE — an unreachable worker would "+
			"then look like a policy regression:\n%s", buf.String())
	}
	if code != cli.ExitUnavailable {
		t.Errorf("exit %d, want %d:\n%s", code, cli.ExitUnavailable, buf.String())
	}
}
