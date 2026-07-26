package cli

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"

	"github.com/lucianoengel/openshield/internal/core"
)

// Restore verification (PLAT-9): the gate that decides whether a restored ledger is EVIDENCE again.
//
// WHY THIS IS NOT `Verify`. Routine verification is allowed to degrade honestly to UNVERIFIED when no
// witness key is supplied — it says what it could and could not establish, which is the right answer to a
// routine question.
//
// A restore is a different question. The operator is asking "did my evidence survive?", and the answer
// "the chain hashes correctly" is one a TRUNCATED ledger also gives: it is internally consistent, it
// simply stops early. Truncation is also the most likely restore failure — a dump taken mid-write, a
// partial restore, a table restored without its tail. Only an external anchor detects it.
//
// So here the witness key is MANDATORY and "I cannot tell" is a FAILURE rather than a success with a
// caveat, because a caveat in a restore report is read as OK.

// RestoreOutcome is the three answers an operator needs to tell apart, because they call for three
// different actions: proceed; your evidence is damaged, do not proceed; your monitoring is broken, fix
// that first. Collapsing the last two into "not OK" sends someone hunting for tampering when the real
// problem is a missing witness key.
const (
	// ExitRestoreVerified means the chain is consistent AND an anchor proves completeness.
	ExitRestoreVerified = 0
	// ExitRestoreDamaged means the chain broke, or completeness could not be established over data that
	// is otherwise readable — tampering or truncation.
	ExitRestoreDamaged = ExitInconsistent
	// ExitRestoreUndetermined means verification could not run: no witness key, unreadable store.
	ExitRestoreUndetermined = ExitUnavailable
)

// RestoreVerify checks that a restored ledger is intact AND complete.
func RestoreVerify(ctx context.Context, w io.Writer, r Reader, anchor, witness ed25519.PublicKey) int {
	if len(witness) != ed25519.PublicKeySize {
		// NOT a degraded success. Without an anchor to check against, the one failure mode a restore is
		// most likely to have is exactly the one that cannot be seen.
		fmt.Fprintf(w, "UNDETERMINED: a witness public key is REQUIRED to verify a restore.\n"+
			"  Chain verification alone cannot detect TRUNCATION — a truncated ledger hashes perfectly and\n"+
			"  simply stops early — and truncation is the most likely way a restore loses evidence.\n")
		return ExitRestoreUndetermined
	}
	res, err := r.Verify(ctx, anchor)
	if err != nil {
		fmt.Fprintf(w, "UNDETERMINED: cannot verify the restored ledger: %v\n", err)
		return ExitRestoreUndetermined
	}
	if !res.Consistent {
		fmt.Fprintf(w, "DAMAGED: the restored ledger's hash chain does not hold: %s\n", res)
		return ExitRestoreDamaged
	}
	if res.Completeness != core.CompletenessAnchored {
		fmt.Fprintf(w, "DAMAGED: the restored ledger is internally consistent but its completeness is "+
			"NOT anchor-proven (%s).\n"+
			"  A consistent chain does not mean nothing was lost: a truncated ledger is consistent.\n"+
			"  Restore is NOT confirmed.\n", res.Completeness)
		return ExitRestoreDamaged
	}
	// Verified — and the report states what that does NOT cover. Completeness is proven only to
	// AnchoredThrough; entries after it can still be truncated undetectably, so reporting bare
	// consistency would let an operator conclude the whole ledger survived when what was established is
	// "everything up to sequence N did".
	unproven := uint64(0)
	if res.ToSequence > res.AnchoredThrough {
		unproven = res.ToSequence - res.AnchoredThrough
	}
	fmt.Fprintf(w, "VERIFIED: %s\n", res)
	fmt.Fprintf(w, "  completeness is anchor-proven through sequence %d\n", res.AnchoredThrough)
	if unproven > 0 {
		fmt.Fprintf(w, "  NOTE: %d entr%s beyond the anchor are NOT completeness-proven — an anchor "+
			"cannot witness what it was written before. Anchor cadence bounds this, not verification.\n",
			unproven, plural(unproven))
	}
	return ExitRestoreVerified
}

func plural(n uint64) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
