package cli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/cli"
	"github.com/lucianoengel/openshield/internal/core"
)

// PLAT-9: restore verification refuses to degrade where routine verification is right to.

func witnessKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func run(t *testing.T, r cli.Reader, witness ed25519.PublicKey) (int, string) {
	t.Helper()
	var b bytes.Buffer
	code := cli.RestoreVerify(context.Background(), &b, r, nil, witness)
	return code, b.String()
}

// TestRestoreWithoutAWitnessKeyIsNotVerified.
//
// Mutation: fall back to `verify`'s honest degraded mode → an unanchored restore reports OK → FAILS.
func TestRestoreWithoutAWitnessKeyIsNotVerified(t *testing.T) {
	r := &fakeReader{res: core.VerifyResult{Consistent: true, Completeness: core.CompletenessAnchored,
		Entries: 10, ToSequence: 10, AnchoredThrough: 10}}
	code, out := run(t, r, nil)
	if code != cli.ExitRestoreUndetermined {
		t.Errorf("exit = %d, want UNDETERMINED — 'I cannot tell' must not render as success in a "+
			"restore report", code)
	}
	if !strings.Contains(out, "TRUNCATION") {
		t.Errorf("the output does not explain WHY a witness key is required: %q", out)
	}
}

// TestConsistentButUnanchoredIsNotVerified is the property that separates this from chain verification: a
// TRUNCATED ledger is internally consistent — it hashes perfectly and simply stops early.
//
// Mutation: accept CompletenessUnverified as success → FAILS.
func TestConsistentButUnanchoredIsNotVerified(t *testing.T) {
	for _, c := range []core.Completeness{core.CompletenessUnverified, core.CompletenessAbsent} {
		r := &fakeReader{res: core.VerifyResult{Consistent: true, Completeness: c, Entries: 10, ToSequence: 10}}
		code, out := run(t, r, witnessKey(t))
		if code != cli.ExitRestoreDamaged {
			t.Errorf("completeness=%v exited %d, want DAMAGED — a consistent chain does not mean nothing "+
				"was lost", c, code)
		}
		if !strings.Contains(out, "NOT confirmed") {
			t.Errorf("the report does not say the restore is unconfirmed: %q", out)
		}
	}
}

// TestVerifiedRestoreReportsTheUnprovenTail — a measure without its bound reads as more than it is.
func TestVerifiedRestoreReportsTheUnprovenTail(t *testing.T) {
	// Fully anchored: verified, with nothing outstanding.
	full := &fakeReader{res: core.VerifyResult{Consistent: true, Completeness: core.CompletenessAnchored,
		Entries: 10, ToSequence: 10, AnchoredThrough: 10}}
	if code, out := run(t, full, witnessKey(t)); code != cli.ExitRestoreVerified ||
		!strings.Contains(out, "VERIFIED") || strings.Contains(out, "NOTE:") {
		t.Errorf("a fully anchored restore: exit=%d out=%q", code, out)
	}

	// Anchored only partway — the common case, since an anchor cannot witness what it was written before.
	partial := &fakeReader{res: core.VerifyResult{Consistent: true, Completeness: core.CompletenessAnchored,
		Entries: 10, ToSequence: 10, AnchoredThrough: 7}}
	code, out := run(t, partial, witnessKey(t))
	if code != cli.ExitRestoreVerified {
		t.Fatalf("exit = %d, want VERIFIED", code)
	}
	if !strings.Contains(out, "3 entries beyond the anchor are NOT completeness-proven") {
		t.Errorf("the unproven tail is not reported: %q — bare consistency would let an operator "+
			"conclude the WHOLE ledger survived, when what was established is 'everything up to 7 did'", out)
	}
}

// TestTheThreeOutcomesAreDistinguishable: proceed / your evidence is damaged / your monitoring is broken
// are three different situations calling for three different actions.
func TestTheThreeOutcomesAreDistinguishable(t *testing.T) {
	w := witnessKey(t)
	verified, _ := run(t, &fakeReader{res: core.VerifyResult{Consistent: true,
		Completeness: core.CompletenessAnchored, ToSequence: 5, AnchoredThrough: 5}}, w)
	damaged, _ := run(t, &fakeReader{res: core.VerifyResult{Consistent: false}}, w)
	undetermined, _ := run(t, &fakeReader{verErr: errors.New("database unreachable")}, w)

	if verified == damaged || damaged == undetermined || verified == undetermined {
		t.Errorf("exit codes collapse (%d/%d/%d) — an operator would hunt for tampering when the real "+
			"problem is a missing witness key", verified, damaged, undetermined)
	}
	if verified != 0 {
		t.Errorf("a verified restore exited %d, want 0", verified)
	}
}
