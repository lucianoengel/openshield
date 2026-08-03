package postgres_test

import (
	"context"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

// TestARestartBeforeTheFirstEntryStillOpens.
//
// Opening the ledger persists the ANCHOR EPOCH; the first entry is written whenever a decision is first
// made, which may be much later, or never on a host that has seen nothing worth recording. Between those
// two moments the database holds a key epoch and no entries — and until this fix, reopening in that state
// failed with "ledger: unavailable: no rows in result set" and the binary exited.
//
// It is not an exotic state. It is: install, start, notice a wrong setting, restart. It is also every
// host whose enforcement was disabled fleet-wide before it decided anything, which is how this was found
// — the SEC-B restart scenario could not get its gateway to start a second time.
//
// The failure was permanent and self-inflicted: every subsequent start hit the same branch, so the
// process could never write the entry that would have let it start. Recovery meant deleting a key_epochs
// row by hand, against an append-only audit store, on the advice of nobody — the error names neither the
// cause nor the fix.
//
// Mutation: call resumeTail unconditionally again (drop the entryCount branch) → the second Open returns
// ErrLedgerUnavailable → this FAILS.
func TestARestartBeforeTheFirstEntryStillOpens(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	signer, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}

	// First boot: the anchor is persisted, and nothing is ever appended.
	l1, err := postgres.Open(ctx, dsn(), signer)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_ = l1.Close()

	// The restart. Same signer, because this is a restart and not a re-enrolment.
	l2, err := postgres.Open(ctx, dsn(), signer)
	if err != nil {
		t.Fatalf("reopening a ledger that was anchored but never written to: %v — a process that starts, "+
			"records nothing and restarts can then never start again", err)
	}
	defer l2.Close()

	// AND IT CONTINUES CORRECTLY, which is the part a looser fix would get wrong. Skipping the tail
	// resume must leave the chain at genesis, not at some arbitrary sequence: the first entry written
	// after this restart has to be sequence 0 committing to the genesis hash, exactly as if the restart
	// had never happened.
	if err := l2.Append(ctx, entry("first-after-restart")); err != nil {
		t.Fatalf("appending after the restart: %v", err)
	}
	res, err := l2.Verify(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Consistent {
		t.Fatalf("the chain does not verify after a restart with no entries: %s", res)
	}
	if res.Entries != 1 || res.ToSequence != 0 {
		t.Errorf("entries=%d to=%d, want 1 and 0 — the restart did not continue from genesis",
			res.Entries, res.ToSequence)
	}
}

// TestAnAnchoredEmptyLedgerStillRefusesAForeignSigner.
//
// The fix adds a branch, and the risk of adding a branch to this function is skipping the check that
// stops two different signers writing one chain. The anchor comparison happens BEFORE the entry-count
// branch, and this pins that ordering: an empty ledger is a reason to start from genesis, never a reason
// to accept a signer that does not own the anchor already stored.
//
// Mutation: move the entryCount branch above the anchor comparison → a foreign signer opens the ledger
// and forks the chain → this FAILS.
func TestAnAnchoredEmptyLedgerStillRefusesAForeignSigner(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	mine, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	l1, err := postgres.Open(ctx, dsn(), mine)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_ = l1.Close()

	foreign, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	l2, err := postgres.Open(ctx, dsn(), foreign)
	if err == nil {
		_ = l2.Close()
		t.Fatal("a signer that does not own the stored anchor was allowed to write an anchored ledger " +
			"just because it held no entries yet — two signers on one chain is the fork the anchor " +
			"check exists to prevent")
	}
}
