package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// DECISION REPLAY (the reproducible half of the thesis).
//
// The platform's claim is that every decision is explainable, REPRODUCIBLE, and cryptographically
// auditable. `openshieldctl verify` has always covered the auditable half — it proves the ledger was
// not edited. The reproducible half was a property of the design that no deployment could be asked to
// demonstrate: `core.Replay` was written, documented and unit-tested, and nothing called it.
//
// WHAT THIS CAN AND CANNOT ESTABLISH, because the distinction is the whole command. The ledger stores
// NO CONTENT (D10/D29) — that is the privacy property the product is built around and it is not being
// relaxed here. So the operator supplies the event, from wherever they still have it, and the question
// answered is narrower than it looks:
//
//	given THIS input, does the policy still produce what was recorded?
//
// It does NOT establish that the input is what the original decision saw. A file event replays against
// the file's CURRENT bytes, so a divergence can mean the policy changed, or the file did. Every
// divergence report says so, because an operator who reverts a policy over a file somebody edited has
// been misled by a report that was technically accurate.

// Dispatcher is the subset of the pipeline a replay needs. An interface rather than the concrete type
// so a test can supply a policy that decides differently without building a second engine.
type Dispatcher interface {
	Dispatch(ctx context.Context, e *corev1.Event) (*corev1.Decision, error)
}

// Replay re-evaluates one event and compares the result with what the ledger recorded for it.
func Replay(ctx context.Context, w io.Writer, r Reader, d Dispatcher, e *corev1.Event) int {
	if e.GetEventId() == "" {
		fmt.Fprintf(w, "UNAVAILABLE: the supplied event carries no event id, so there is nothing to "+
			"look up in the ledger.\n")
		return ExitUnavailable
	}
	entries, err := r.Entries(ctx)
	if err != nil {
		fmt.Fprintf(w, "UNAVAILABLE: cannot read the ledger: %v\n", err)
		return ExitUnavailable
	}

	var found []*core.Entry
	for _, ent := range entries {
		if ent.Decision.GetEventId() == e.GetEventId() {
			found = append(found, ent)
		}
	}
	switch len(found) {
	case 0:
		// NOT a divergence. "The policy produced something different" and "there is no record of this
		// decision" call for different responses, and collapsing them would let a typo in an event id
		// read as a policy regression.
		fmt.Fprintf(w, "UNAVAILABLE: no ledger entry records a decision for event %q.\n"+
			"  This is not a divergence — there is nothing to compare against.\n", e.GetEventId())
		return ExitUnavailable
	case 1:
	default:
		// Comparing against an arbitrary one would produce a confident answer about the wrong record.
		fmt.Fprintf(w, "UNAVAILABLE: %d ledger entries record a decision for event %q.\n"+
			"  An event that produced several decisions was either re-processed or is a bug; either way\n"+
			"  the right one to compare against is not this command's guess to make.\n",
			len(found), e.GetEventId())
		return ExitUnavailable
	}
	recorded := found[0].Decision

	got, derr := d.Dispatch(ctx, e)
	if derr != nil {
		fmt.Fprintf(w, "UNAVAILABLE: re-evaluating the event failed: %v\n", derr)
		return ExitUnavailable
	}

	if eqErr := core.DecisionsEquivalent(recorded, got); eqErr != nil {
		fmt.Fprintf(w, "DIVERGED: replaying event %q does not reproduce the recorded decision.\n"+
			"  %v\n", e.GetEventId(), eqErr)
		// The policy that DECIDED and the policy that just RAN, named side by side. A divergence
		// explained by "you are running a different policy" is not a regression and must not read like
		// one.
		if recorded.GetPolicyId() != got.GetPolicyId() || recorded.GetPolicyVersion() != got.GetPolicyVersion() {
			fmt.Fprintf(w, "  recorded under policy %s@%s; replayed under %s@%s\n",
				recorded.GetPolicyId(), recorded.GetPolicyVersion(),
				got.GetPolicyId(), got.GetPolicyVersion())
		}
		fmt.Fprintf(w, "  CAUSE IS AMBIGUOUS: the ledger stores no content, so this replay read the "+
			"input as it is NOW.\n"+
			"  A divergence means the POLICY changed or the INPUT changed. Establish which before "+
			"treating it as a regression.\n")
		return ExitInconsistent
	}

	fmt.Fprintf(w, "REPRODUCED: event %q re-evaluates to the recorded decision (%s, confidence %.2f)\n",
		e.GetEventId(), recorded.GetAction(), recorded.GetConfidence())
	fmt.Fprintf(w, "  policy %s@%s\n", got.GetPolicyId(), got.GetPolicyVersion())
	fmt.Fprintf(w, "  NOTE: this establishes that the policy produces the recorded decision FROM THIS "+
		"INPUT.\n"+
		"  It does not establish that this input is what the original decision saw — the ledger keeps "+
		"no content.\n")
	return ExitOK
}
