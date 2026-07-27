package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/lucianoengel/openshield/internal/backup"
	"github.com/lucianoengel/openshield/internal/cli"
)

// THE BACKUP AND RESTORE DRILL, finally driven by something (D315).
//
// `internal/backup` was written with care: it deliberately does not wrap pg_dump in Go, it owns the
// ARGUMENTS so they are not retyped from a wiki, and it owns THE ORDER so a restore is not called
// finished until the ledger re-verifies. `DumpArgs`, `Script` and `DrillSteps` had no caller. The
// procedure existed as a library nobody could run.
//
// That matters more here than for most unwired code, because the thing it protects is the SYSTEM OF
// RECORD. The audit ledger is the product's central claim — tamper-evident, forward-secure, anchored —
// and all of that is worth nothing against a disk failure if the backup procedure is a package in a
// repository. A control that cannot survive its own infrastructure failing is a control with an
// unexamined single point of failure.
//
// THE PROPERTY WORTH KEEPING is the one the package's own doc names: a restore is not finished until
// `restore-verify` passes. A byte-perfect pg_restore that produces an unverifiable ledger is a FAILED
// restore — the bytes came back and the evidence did not. This command therefore runs verification as
// part of the drill and reports the drill's outcome, never the restore's.
//
// IT RUNS THE STEPS RATHER THAN ONLY PRINTING THEM, with `--print` for the operator who wants the script
// to put in their own runbook. Printing only would have been the safer-looking choice and the worse one:
// a drill nobody runs is exactly the state this whole area was already in.

const backupUsage = `usage:
  openshieldctl backup dump --file DUMP [--dsn DSN]
      back up the system of record (pg_dump, custom format)

  openshieldctl backup drill --file DUMP --witness FILE [--anchor FILE] [--dsn DSN]
      RESTORE the dump and re-verify the ledger. The drill fails unless verification
      passes: a restore that returns bytes but not evidence is a failed restore.

  openshieldctl backup drill --print ...
      print the drill as a shell script instead of running it
`

func backupCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, backupUsage)
		return cli.ExitUnavailable
	}
	sub, rest := args[0], args[1:]
	f := parseBackupFlags(rest)
	opts := backup.Options{
		DSN:     valueOr(f, "dsn", os.Getenv("OPENSHIELD_DSN")),
		File:    f["file"],
		Anchor:  f["anchor"],
		Witness: f["witness"],
	}
	if opts.DSN == "" {
		opts.DSN = "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"
	}
	if opts.File == "" {
		fmt.Fprint(os.Stderr, backupUsage)
		return cli.ExitUnavailable
	}

	switch sub {
	case "dump":
		return runStep(backup.DumpArgs(opts), "backup")
	case "drill":
		if _, printOnly := f["print"]; printOnly {
			script, err := backup.Script(opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
				return cli.ExitUnavailable
			}
			fmt.Print(script)
			return 0
		}
		steps, err := backup.DrillSteps(opts)
		if err != nil {
			// ErrNoWitness reads as an instruction, not a complaint: without an anchor to check against,
			// TRUNCATION is undetectable, and truncation is the most likely way a restore loses evidence.
			fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
			return cli.ExitUnavailable
		}
		for _, step := range steps {
			if code := runStep(step, "drill"); code != 0 {
				// STOPS AT THE FIRST FAILURE. Carrying on would mean verifying whatever was already in
				// the database after a failed restore — which can pass, and would be a green drill over
				// a restore that never happened.
				fmt.Fprintf(os.Stderr, "openshieldctl: restore drill FAILED at: %s\n", strings.Join(step, " "))
				return code
			}
		}
		fmt.Fprintln(os.Stderr, "openshieldctl: restore drill PASSED — the ledger re-verified against "+
			"its anchors, so the evidence came back and not merely the bytes")
		return 0
	default:
		fmt.Fprint(os.Stderr, backupUsage)
		return cli.ExitUnavailable
	}
}

// runStep executes one step, passing its output through.
//
// THE EXIT CODE IS PROPAGATED, not flattened to 0/1: `restore-verify` returns 3 for TAMPERED and 4 for
// UNAVAILABLE, and those mean different things to whoever is holding the pager. Collapsing them would
// turn "the restored ledger does not verify" into the same signal as "the database was unreachable".
func runStep(argv []string, what string) int {
	fmt.Fprintf(os.Stderr, "openshieldctl: %s: %s\n", what, strings.Join(argv, " "))
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- argv is built by internal/backup, not user input
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		// A MISSING TOOL IS NAMED. "pg_dump: no such file" from a wrapper reads as an OpenShield bug;
		// what it actually means is that the database's client tools are not installed on this host.
		fmt.Fprintf(os.Stderr, "openshieldctl: could not run %s: %v\n(is %s installed and on PATH?)\n",
			argv[0], err, argv[0])
		return cli.ExitUnavailable
	}
	return 0
}

func parseBackupFlags(args []string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--") {
			continue
		}
		key := strings.TrimPrefix(args[i], "--")
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			out[key] = args[i+1]
			i++
			continue
		}
		out[key] = "" // a bare flag, e.g. --print
	}
	return out
}

func valueOr(f map[string]string, key, fallback string) string {
	if v, ok := f[key]; ok && v != "" {
		return v
	}
	return fallback
}
