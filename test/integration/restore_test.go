//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE BACKUP AND RESTORE DRILL (PLAT-9, `openshieldctl backup dump` / `backup drill` / `restore-verify`).
//
// The audit ledger is the product's central claim — tamper-evident, forward-secure, anchored — and every
// bit of that is worth nothing against a disk failure if the recovery procedure has never been executed.
// `internal/backup` was written with care and, until D315, had no caller at all; even after it got one,
// no scenario had ever taken a dump and restored it.
//
// THE CLAIM UNDER TEST is the one the package's own doc makes: a restore is NOT FINISHED until
// `restore-verify` passes. A byte-perfect `pg_restore` that produces an unverifiable ledger is a FAILED
// restore — the bytes came back and the evidence did not — and the difference between those two is the
// entire reason this command exists rather than an operator eyeballing a row count.
//
// The restore target is a SEPARATE DATABASE on the same server. A drill that restored over the source
// would destroy the thing it is meant to prove recoverable, and would also let a "restore" that did
// nothing at all pass, since the data was already there.

// ledgerStack starts an engine and waits for real ledger entries. Real ones, not hand-inserted: the
// chain, the signatures and the key epoch all have to be what the engine actually produces, or a restore
// that mangles any of them still verifies.
func ledgerStack(t *testing.T, want int) (*Stack, string) {
	t.Helper()
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	watch := t.TempDir()

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
	})
	eng.WaitForOutput("engine observing", 90*time.Second)

	// KEEP WRITING until the ledger fills, with a fresh name each round. "engine observing" is printed
	// when the watcher is set up, not when the kernel has begun delivering for this directory, and a
	// scenario that writes once into that window sees no events at all and reads as a broken pipeline.
	// This is the same resend discipline the syslog scenarios use, for the same reason.
	pool := openPool(t, stack.DSN)
	round := 0
	Eventually(t, 180*time.Second, "the ledger to hold entries worth backing up", func() bool {
		for i := 0; i < want; i++ {
			name := filepath.Join(watch, fmt.Sprintf("c%d-%d.csv", round, i))
			if err := os.WriteFile(name, []byte("cpf\n111.444.777-35\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		round++
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n)
		return n >= want
	})

	// THE ENGINE IS STOPPED BEFORE THE LEDGER IS USED, and leaving it running made this test flaky in a
	// way that pointed at the product rather than at the test.
	//
	// The loop above keeps WRITING each round until the count crosses `want`, so when it finally does,
	// files from the last round are still in flight. Entries then land AFTER the caller anchors the head
	// and before it takes the dump — and the restored ledger's head is past its anchor, which
	// restore-verify correctly reports as "internally consistent but its completeness is NOT anchor-proven".
	//
	// That is the right verdict for the data it was given. The bug was that the test kept moving the head
	// after promising not to. Observed once in CI (run 30579395550) on a commit that only added a test
	// file to another package, which is how it was identified as a harness race rather than a regression.
	eng.Stop()

	// And the count must be STABLE afterwards, or the stop did not take and the race is merely narrower.
	var settled int
	if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&settled); err != nil {
		t.Fatalf("reading the settled ledger size: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	var after int
	if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&after); err != nil {
		t.Fatalf("re-reading the settled ledger size: %v", err)
	}
	if after != settled {
		t.Fatalf("the ledger is still growing after the engine was stopped (%d -> %d); anchoring it now "+
			"would produce an anchor the head immediately outruns", settled, after)
	}
	return stack, work
}

// witnessKeys mints a witness keypair via the shipped provisioning tool rather than in Go, so the drill
// uses the same key material an operator would have.
func witnessKeys(t *testing.T, dir string) (pub, priv string) {
	t.Helper()
	wdir := filepath.Join(dir, "witness")
	if out, err := runCapture(t, "openshield-provision", nil, "witness-keygen", "--out", wdir); err != nil {
		t.Fatalf("witness-keygen: %v\n%s", err, out)
	}
	return filepath.Join(wdir, "witness-pub"), filepath.Join(wdir, "witness-priv")
}

// TestARestoredLedgerVerifiesAndATruncatedOneIsRefused is the whole drill, and the two halves are the
// point: a good restore must be CONFIRMED, and the failure a restore is most likely to actually have
// must be REFUSED.
//
// TRUNCATION IS THAT FAILURE, and it is the one a hash chain cannot see. Drop entries from the tail and
// what remains still chains perfectly — every entry still commits to its predecessor, verification walks
// it happily and reports a consistent ledger that simply stops earlier than it should. Only the external
// anchor, written when the head was further along, can say that something used to be there. That is what
// D64's completeness is FOR, and this is the scenario that distinguishes it from decoration.
func TestARestoredLedgerVerifiesAndATruncatedOneIsRefused(t *testing.T) {
	stack, work := ledgerStack(t, 3)
	pub, priv := witnessKeys(t, work)

	// Anchor the head, so the backup carries a completeness proof and not merely a chain.
	if out, err := runCapture(t, "openshield-anchor", nil, "--dsn", stack.DSN, "--witness", priv); err != nil {
		t.Fatalf("anchoring the head before the backup: %v\n%s", err, out)
	}

	dump := filepath.Join(work, "ledger.dump")
	if out, err := runCapture(t, "openshieldctl", nil, "backup", "dump",
		"--dsn", stack.DSN, "--file", dump); err != nil {
		t.Fatalf("taking the backup: %v\n%s", err, out)
	}
	st, err := os.Stat(dump)
	if err != nil || st.Size() == 0 {
		t.Fatalf("the backup produced no dump file (%v). A command that reports success and writes "+
			"nothing is the worst possible backup: the failure surfaces only during the recovery", err)
	}

	// RESTORE INTO A FRESH DATABASE, via the shipped DRILL rather than by calling pg_restore here.
	// Restoring over the source would destroy the thing being proven recoverable and would let a restore
	// that did nothing at all pass, since the data was already there.
	//
	// The drill's last step shells out to `openshieldctl` BY NAME, so the built binary has to be on PATH
	// — which is itself worth exercising: an operator whose drill cannot find the verification step gets
	// a restore that stops after pg_restore, and that is the failure this command exists to prevent.
	restored := stack.DSNFor(t, "restored")
	binPath := "PATH=" + filepath.Dir(Binary(t, "openshieldctl")) + ":" + os.Getenv("PATH")
	out, err := runCapture(t, "openshieldctl", []string{binPath}, "backup", "drill",
		"--dsn", restored, "--file", dump, "--witness", pub)
	if err != nil {
		t.Fatalf("the restore drill failed: %v\n%s", err, out)
	}
	if !contains(out, "drill PASSED") {
		t.Fatalf("the drill did not report passing:\n%s", out)
	}

	rpool := openPool(t, restored)
	var got int
	if err := rpool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&got); err != nil {
		t.Fatalf("the restored database has no readable ledger: %v", err)
	}
	if got < 3 {
		t.Fatalf("the restored ledger holds %d entries, want at least 3 — the restore returned but the "+
			"evidence did not come with it", got)
	}

	// 1. THE GOOD RESTORE IS CONFIRMED. Without this half, the refusal below is satisfied by a command
	// that refuses every restore, which is not a gate but an outage during a disaster.
	out, err = runCapture(t, "openshieldctl", nil, "restore-verify",
		"--dsn", restored, "--witness", pub)
	if err != nil {
		t.Fatalf("a faithful restore was NOT confirmed: %v\n%s", err, out)
	}
	if !contains(out, "VERIFIED") || !contains(out, "anchor-proven") {
		t.Errorf("the restore report does not state that completeness is anchor-proven. A report saying "+
			"only that the chain holds lets an operator conclude the whole ledger survived, when what "+
			"was established is that everything up to the anchor did:\n%s", out)
	}

	// 2. TRUNCATION — losing entries from the TAIL. The realistic loss: a dump taken mid-write, a restore
	// interrupted, a replica that fell behind. It is precisely the loss that leaves the chain intact.
	//
	// THE DATABASE REFUSES THE DELETE, which is migration 010's append-only guard doing its job, and is
	// worth asserting on the way past rather than working around silently — it is the requirement that
	// says the ledger cannot be edited through ordinary SQL.
	if _, err := rpool.Exec(Ctx(t),
		`DELETE FROM audit_entries WHERE sequence = (SELECT max(sequence) FROM audit_entries)`); err == nil {
		t.Fatal("a DELETE against audit_entries SUCCEEDED — the append-only guard is not installed on " +
			"the restored database, which means a restore silently drops the protection the original had")
	} else if !contains(err.Error(), "append-only") {
		t.Fatalf("the DELETE failed for some other reason: %v", err)
	}

	// So the truncation is constructed the way real loss produces it: the rows are simply NOT THERE. The
	// guard is honest-bounded — migration 013 records that a table OWNER can disable it — and the drill
	// connects as the owner, which is exactly the credential a disaster-recovery operator holds. Dropping
	// the trigger here is therefore not cheating around the product; it is standing in for a restore that
	// never received the rows in the first place, which no trigger can prevent.
	if _, err := rpool.Exec(Ctx(t),
		`ALTER TABLE audit_entries DISABLE TRIGGER openshield_audit_append_only_trg`); err != nil {
		t.Fatalf("disabling the guard to construct a truncated ledger: %v", err)
	}
	if _, err := rpool.Exec(Ctx(t),
		`DELETE FROM audit_entries WHERE sequence = (SELECT max(sequence) FROM audit_entries)`); err != nil {
		t.Fatal(err)
	}
	if _, err := rpool.Exec(Ctx(t),
		`ALTER TABLE audit_entries ENABLE TRIGGER openshield_audit_append_only_trg`); err != nil {
		t.Fatal(err)
	}

	// THE HASH CHAIN STILL HOLDS, and this is the premise of the whole scenario rather than a detail.
	// Verification WITHOUT the witness key walks the truncated ledger, finds every entry committing to
	// its predecessor, and reports a perfectly consistent chain that simply stops one entry early. If
	// hashing alone could catch this, the anchor would be proving nothing.
	//
	// `consistent=true` in full, NOT the substring "consistent" — which also matches `consistent=false`,
	// and did: the first version of this assertion passed against a ledger reported as INCONSISTENT, and
	// so let a mutation through that removed a check.
	chain, cerr := runCapture(t, "openshieldctl", nil, "verify", "--dsn", restored)
	if cerr != nil {
		t.Fatalf("after truncation the witness-less chain check FAILED. The scenario needs it to pass — "+
			"a truncated chain hashes perfectly — so something else is being detected: %v\n%s", cerr, chain)
	}
	if !contains(chain, "consistent=true") {
		t.Fatalf("the truncated ledger did not report a consistent chain, so the premise does not "+
			"hold:\n%s", chain)
	}
	if !contains(chain, "completeness=unverified") {
		t.Errorf("a witness-less verification of a truncated ledger did not report completeness as "+
			"UNVERIFIED. That word is the entire warning an operator gets that consistency is not "+
			"survival:\n%s", chain)
	}

	// AND THE ANCHOR IS WHAT CATCHES IT. Same ledger, same command, one extra input — the witness key —
	// and the verdict inverts, because the anchor was written when the head was further along and the
	// chain can no longer satisfy it.
	anchored, aerr := runCapture(t, "openshieldctl", nil, "verify", "--dsn", restored, "--witness", pub)
	if aerr == nil {
		t.Errorf("verification WITH the witness key accepted a ledger truncated past its anchor. The "+
			"anchor is the only thing that knows an entry used to be there:\n%s", anchored)
	}

	// AND THE RESTORE IS REFUSED ANYWAY. Same database, same intact chain; the anchor is the only thing
	// that knows an entry is missing.
	out, err = runCapture(t, "openshieldctl", nil, "restore-verify",
		"--dsn", restored, "--witness", pub)
	if err == nil {
		t.Fatalf("a TRUNCATED ledger was confirmed as a good restore. A truncated ledger hashes "+
			"perfectly and simply stops early, so this passing means completeness is not being checked "+
			"against the anchor at all:\n%s", out)
	}
	if !contains(out, "DAMAGED") {
		t.Errorf("the truncated restore was not reported as DAMAGED, so an operator cannot tell it from "+
			"a verification that could not run:\n%s", out)
	}
}

// TestARestoreWithoutAWitnessIsUndeterminedNotOk.
//
// The degrade is the danger. `verify` may report UNVERIFIED completeness and still exit zero — that is
// the honest degraded mode for day-to-day use. A RESTORE report must not do the same, because it is read
// exactly once, at the moment somebody is deciding whether the evidence survived, and the one failure it
// is most likely to have is the one it cannot see without the anchor.
//
// So this asserts the absence of a friendly fallback: no witness, no verdict — and a non-zero exit, since
// an operator's script reads the status and not the prose.
func TestARestoreWithoutAWitnessIsUndeterminedNotOk(t *testing.T) {
	stack, work := ledgerStack(t, 1)
	pub, priv := witnessKeys(t, work)
	if out, err := runCapture(t, "openshield-anchor", nil, "--dsn", stack.DSN, "--witness", priv); err != nil {
		t.Fatalf("anchoring: %v\n%s", err, out)
	}

	// WITH the witness it is confirmed — same database, one flag apart, so the refusal below is about the
	// missing key and not about this ledger being unverifiable for some other reason.
	if out, err := runCapture(t, "openshieldctl", nil, "restore-verify",
		"--dsn", stack.DSN, "--witness", pub); err != nil {
		t.Fatalf("an anchored ledger was not confirmed even WITH a witness key, so the comparison "+
			"below isolates nothing: %v\n%s", err, out)
	}

	out, err := runCapture(t, "openshieldctl", nil, "restore-verify", "--dsn", stack.DSN)
	if err == nil {
		t.Fatalf("restore-verify reported success with NO witness key. It cannot have checked "+
			"completeness, so it confirmed a restore whose most likely failure it is blind to:\n%s", out)
	}
	if !contains(out, "UNDETERMINED") {
		t.Errorf("the witness-less report does not say UNDETERMINED. 'Damaged' and 'I could not tell' "+
			"call for different responses during a recovery:\n%s", out)
	}
	if !contains(out, "TRUNCATION") {
		t.Errorf("the report does not say WHY a witness is required — that chain verification alone "+
			"cannot detect truncation. An operator told only 'key required' will supply any key or "+
			"skip the step:\n%s", out)
	}
}
