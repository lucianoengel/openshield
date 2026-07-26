// Package backup builds the backup and restore-drill procedures for the system of record (PLAT-9).
//
// It deliberately does NOT wrap pg_dump in Go. The database's own tools are the ones an operator's DBA
// already trusts and already monitors, and re-implementing them would mean owning their failure modes
// without their maturity. What this package owns is the part that is OpenShield's: the ARGUMENTS, so they
// are not retyped from a wiki, and THE ORDER, so a restore is not called finished until the ledger
// re-verifies.
//
// THE PROPERTY THAT MATTERS: a restore drill ends with `restore-verify`, and a failure there fails the
// drill. A byte-perfect pg_restore that produces an unverifiable ledger is a FAILED restore — the bytes
// came back, the evidence did not — and any procedure that reports success before checking is one that
// will eventually report success on a truncated ledger.
package backup

import (
	"errors"
	"strings"
)

// Options are what a drill needs to know.
type Options struct {
	DSN string
	// File is the dump file. Custom format (--format=custom), because a plain SQL dump cannot be restored
	// selectively and is far slower to load — an operator restoring under pressure needs neither surprise.
	File string
	// Anchor and Witness are what verification needs. Witness is MANDATORY for a drill: without an anchor
	// to check against, the most likely restore failure — truncation — is the one that cannot be seen, and
	// a drill that cannot detect it is a rehearsal of the wrong thing.
	Anchor  string
	Witness string
}

// DumpArgs is the backup command.
func DumpArgs(o Options) []string {
	return []string{"pg_dump", "--format=custom", "--no-owner", "--no-privileges",
		"--file=" + o.File, o.DSN}
}

// RestoreArgs is the restore command.
//
// --clean --if-exists so a restore into a populated database is deterministic rather than a merge: a
// half-merged system of record is worse than either a clean restore or a clean failure.
//
// --exit-on-error because a restore that carried on past a failure is exactly the case where the
// verification afterwards would be reporting on a partially-loaded ledger.
func RestoreArgs(o Options) []string {
	return []string{"pg_restore", "--clean", "--if-exists", "--exit-on-error",
		"--no-owner", "--no-privileges", "--dbname=" + o.DSN, o.File}
}

// VerifyArgs is the step that decides whether the restore SUCCEEDED.
func VerifyArgs(o Options) []string {
	args := []string{"openshieldctl", "restore-verify", "--dsn", o.DSN}
	if o.Anchor != "" {
		args = append(args, "--anchor", o.Anchor)
	}
	if o.Witness != "" {
		args = append(args, "--witness", o.Witness)
	}
	return args
}

// ErrNoWitness is returned when a drill is requested without a witness key.
var ErrNoWitness = errors.New("backup: a restore drill needs a witness key — without an anchor to check " +
	"against, TRUNCATION is undetectable, and truncation is the most likely way a restore loses evidence")

// DrillSteps is the ordered restore drill. The LAST step is verification, and a caller that stops before
// it has not completed a drill — it has completed a copy.
func DrillSteps(o Options) ([][]string, error) {
	if strings.TrimSpace(o.Witness) == "" {
		return nil, ErrNoWitness
	}
	return [][]string{RestoreArgs(o), VerifyArgs(o)}, nil
}

// Script renders the drill as a shell script that FAILS if any step fails.
//
// `set -euo pipefail` is not decoration: without it a failed pg_restore would be followed by a
// verification of whatever was already in the database, which could pass — a green drill over a restore
// that never happened.
func Script(o Options) (string, error) {
	steps, err := DrillSteps(o)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n")
	b.WriteString("# A restore is NOT finished until the ledger re-verifies. Any step failing fails the drill.\n")
	for _, s := range steps {
		b.WriteString(strings.Join(s, " ") + "\n")
	}
	b.WriteString("echo 'restore drill PASSED: the ledger re-verified against its anchors'\n")
	return b.String(), nil
}
