package backup_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/backup"
)

// PLAT-9: the backup and restore-drill procedure.

func opts() backup.Options {
	return backup.Options{DSN: "postgres://x/y", File: "/backups/os.dump",
		Anchor: "/etc/openshield/anchor.pub", Witness: "/etc/openshield/witness.pub"}
}

func joined(args []string) string { return strings.Join(args, " ") }

// TestADrillENDSWithVerification is the whole point: a byte-perfect pg_restore that produces an
// unverifiable ledger is a FAILED restore — the bytes came back, the evidence did not.
//
// Mutation: drop the verify step (drill = restore only) → FAILS.
func TestADrillEndsWithVerification(t *testing.T) {
	steps, err := backup.DrillSteps(opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) < 2 {
		t.Fatalf("drill has %d step(s) — a restore without a verification is a COPY, not a drill", len(steps))
	}
	last := steps[len(steps)-1]
	if last[0] != "openshieldctl" || last[1] != "restore-verify" {
		t.Errorf("the drill's LAST step is %v, want restore-verify — anything after verification could "+
			"report success on a ledger that never verified", last)
	}
	if !strings.Contains(joined(last), "--witness") {
		t.Error("the verification step carries no witness key, so truncation would be undetectable")
	}
	// And restore comes first: verifying before restoring would verify the OLD database.
	if steps[0][0] != "pg_restore" {
		t.Errorf("the drill's first step is %v, want pg_restore", steps[0])
	}
}

// TestADrillWithoutAWitnessIsRefused — a drill that cannot detect truncation is a rehearsal of the wrong
// thing.
//
// Mutation: allow a witness-less drill → FAILS.
func TestADrillWithoutAWitnessIsRefused(t *testing.T) {
	o := opts()
	o.Witness = ""
	if _, err := backup.DrillSteps(o); !errors.Is(err, backup.ErrNoWitness) {
		t.Errorf("err = %v, want ErrNoWitness", err)
	}
	if _, err := backup.Script(o); err == nil {
		t.Error("a witness-less drill script was produced")
	}
}

// TestTheScriptFailsOnAnyStep — without `set -e`, a failed pg_restore would be followed by a verification
// of whatever was ALREADY in the database, which could pass: a green drill over a restore that never
// happened.
//
// Mutation: drop `set -euo pipefail` → FAILS.
func TestTheScriptFailsOnAnyStep(t *testing.T) {
	s, err := backup.Script(opts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "set -euo pipefail") {
		t.Error("the drill script does not abort on a failed step — a failed restore would be followed " +
			"by a verification of the database that was already there, which could PASS")
	}
	// Verification must be the last command before the success message, not buried mid-script.
	verifyAt := strings.Index(s, "restore-verify")
	restoreAt := strings.Index(s, "pg_restore")
	if verifyAt < 0 || restoreAt < 0 || verifyAt < restoreAt {
		t.Errorf("the script verifies before it restores, or not at all:\n%s", s)
	}
	if !strings.Contains(s, "PASSED") {
		t.Error("the script reports nothing on success — a drill nobody can see the result of is one " +
			"nobody runs twice")
	}
}

// TestRestoreIsDeterministicNotAMerge: a half-merged system of record is worse than either a clean
// restore or a clean failure.
func TestRestoreIsDeterministicNotAMerge(t *testing.T) {
	got := joined(backup.RestoreArgs(opts()))
	for _, want := range []string{"--clean", "--if-exists", "--exit-on-error"} {
		if !strings.Contains(got, want) {
			t.Errorf("restore args %q lack %s", got, want)
		}
	}
	if d := joined(backup.DumpArgs(opts())); !strings.Contains(d, "--format=custom") {
		t.Errorf("dump args %q are not custom format — a plain SQL dump cannot be restored selectively "+
			"and is far slower to load, neither of which an operator wants under pressure", d)
	}
}
