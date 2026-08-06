package cli

import (
	"context"
	"fmt"
	"io"

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

// Replay re-evaluates one event and compares the result with what the ledger recorded for it, printing
// the answer as prose and returning the process exit code.
//
// IT IS A RENDERER. The comparison itself lives in ReplayResultFor, which the operator API also calls
// (CONSOLE-10) — because an operator who gets "REPRODUCED" from the console and "DIVERGED" from the CLI
// has learned only that the product cannot be trusted about the one thing it claims to be good at.
func Replay(ctx context.Context, w io.Writer, r Reader, d Dispatcher, e *corev1.Event) int {
	res := ReplayResultFor(ctx, r, d, e)
	switch res.Outcome {
	case ReplayUnavailable:
		fmt.Fprintf(w, "UNAVAILABLE: %s.\n", res.Reason)
		return ExitUnavailable
	case ReplayDiverged:
		fmt.Fprintf(w, "DIVERGED: replaying event %q does not reproduce the recorded decision.\n"+
			"  %s\n", res.EventID, res.Reason)
		// The policy that DECIDED and the policy that just RAN, named side by side. A divergence
		// explained by "you are running a different policy" is not a regression and must not read like
		// one.
		if res.RecordedPolicyID != res.ReplayedPolicyID ||
			res.RecordedPolicyVersion != res.ReplayedPolicyVersion {
			fmt.Fprintf(w, "  recorded under policy %s@%s; replayed under %s@%s\n",
				res.RecordedPolicyID, res.RecordedPolicyVersion,
				res.ReplayedPolicyID, res.ReplayedPolicyVersion)
		}
		fmt.Fprintf(w, "  CAUSE IS AMBIGUOUS: %s\n", res.Caveat)
		return ExitInconsistent
	}

	fmt.Fprintf(w, "REPRODUCED: event %q re-evaluates to the recorded decision (%s, confidence %.2f)\n",
		res.EventID, res.RecordedAction, res.Confidence)
	fmt.Fprintf(w, "  policy %s@%s\n", res.ReplayedPolicyID, res.ReplayedPolicyVersion)
	fmt.Fprintf(w, "  NOTE: %s\n", res.Caveat)
	return ExitOK
}
