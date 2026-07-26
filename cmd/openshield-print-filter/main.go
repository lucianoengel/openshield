// Command openshield-print-filter is a CUPS filter that decides a print job before it prints (DLP-2b).
//
// CUPS runs a job through a chain of filters, invoking each as
//
//	filter job-id user title copies options [filename]
//
// with the job on stdin when no filename is given, and the transformed job expected on stdout. The property
// that makes this ENFORCEMENT rather than reporting: **a non-zero exit aborts the job**. No driver, no
// hooking, no injection — the spooler already provides the interposition point, exactly as X11's selection
// ownership does for the clipboard (D247).
//
// This binary parses NOTHING. It streams the job to the engine, which classifies it in the sandboxed worker
// (D71/D29), and then either copies the job through byte-for-byte or exits non-zero. A print filter runs on
// documents from anywhere, so it is precisely the attacker-controlled-bytes case that must not be parsed in
// a process sitting in the print path.
//
// FAIL-OPEN is deliberate (D17/D73): if the engine is unreachable, slow, or broken, the job PRINTS and the
// failure is reported loudly on stderr (which CUPS captures into the job log). A DLP that stops an office
// printing because a daemon died is a DLP that gets uninstalled, which protects nothing.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/lucianoengel/openshield/internal/printguard"
)

func logf(format string, a ...any) {
	// CUPS treats stderr lines prefixed with a level as log messages; ERROR/INFO are surfaced to operators.
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

func main() {
	// CUPS calls filters with 5 or 6 arguments. Anything else means we were invoked wrongly; pass the job
	// through rather than break printing on a misconfiguration.
	if len(os.Args) < 6 {
		logf("ERROR: openshield-print-filter: expected CUPS filter arguments; passing the job through")
		_, _ = io.Copy(os.Stdout, os.Stdin)
		return
	}
	user, title := os.Args[2], os.Args[3]
	printer := os.Getenv("PRINTER")

	in := io.Reader(os.Stdin)
	if len(os.Args) >= 7 && os.Args[6] != "" {
		f, err := os.Open(os.Args[6])
		if err != nil {
			logf("ERROR: openshield-print-filter: opening the job file: %v; passing through", err)
			_, _ = io.Copy(os.Stdout, os.Stdin)
			return
		}
		defer f.Close()
		in = f
	}

	socket := os.Getenv("OPENSHIELD_PRINT_SOCKET")
	if socket == "" {
		logf("INFO: openshield-print-filter: no verdict socket configured; passing the job through")
		_, _ = io.Copy(os.Stdout, in)
		return
	}

	// Read up to the cap for classification, and remember it so an allowed job is reproduced EXACTLY: the
	// head we buffered plus the untouched remainder. A filter that altered the job would corrupt printing.
	head := make([]byte, 0, 64*1024)
	buf := make([]byte, 32*1024)
	for len(head) < printguard.MaxJobBytes {
		n, err := in.Read(buf)
		if n > 0 {
			head = append(head, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	var idb [8]byte
	_, _ = rand.Read(idb[:])
	req := printguard.Request{
		ID:       binary.BigEndian.Uint64(idb[:]),
		Printer:  printer,
		User:     user,
		HasTitle: title != "", // whether, never what: a document title is often the sensitive fact itself
		Job:      head,
	}

	verdict, err := printguard.Ask(socket, req, printguard.DefaultTimeout)
	if err != nil {
		// FAIL OPEN, loudly. This is the load-bearing availability property, not an oversight.
		logf("ERROR: openshield-print-filter: no verdict (%v) — FAILING OPEN, the job prints unchecked", err)
		writeThrough(head, in)
		return
	}
	if verdict == printguard.VerdictDeny {
		// Emit NOTHING and exit non-zero: CUPS aborts the job, so no page is produced.
		logf("ERROR: openshield-print-filter: job REFUSED by policy (user=%q printer=%q %d bytes)",
			user, printer, len(head))
		os.Exit(1)
	}
	writeThrough(head, in)
}

// writeThrough reproduces the job byte-for-byte: the buffered head first, then whatever remains unread.
func writeThrough(head []byte, rest io.Reader) {
	if _, err := os.Stdout.Write(head); err != nil {
		logf("ERROR: openshield-print-filter: writing the job: %v", err)
		os.Exit(1)
	}
	if _, err := io.Copy(os.Stdout, rest); err != nil {
		logf("ERROR: openshield-print-filter: copying the job tail: %v", err)
		os.Exit(1)
	}
}
