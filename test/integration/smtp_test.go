//go:build integration

package integration

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE SMTP CAPTURE CONNECTOR END TO END (SMTP-1, OPENSHIELD_SMTP_LISTEN).
//
// The connector was COMPLETE and started by NOTHING: a session parser, a capture listener with
// per-session size ceilings, idle timeouts and a concurrency cap, an event producer, and unit tests for
// all of it — imported by no binary, with no configuration setting that could have turned it on. It
// could not run in any deployment however configured, while the README described the product as
// performing live SMTP inspection.
//
// It was found by asking the code graph for exported symbols with no non-test caller — the check D341
// proposed after the third instance of this shape, and this was its first run.
//
// The scenario asserts on the AUDIT ROW, and specifically on an ALERT, because that is what separates
// "the message was parsed" from "the message was CLASSIFIED": the body travels out of band to the
// sandboxed worker (ENG-1/D72), and only a detection proves it arrived.

// smtpDeliver speaks a real SMTP session and delivers body. It returns once the server has accepted the
// message, so the caller knows the transcript is complete rather than guessing with a sleep.
func smtpDeliver(t *testing.T, addr, from, to, body string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		t.Fatalf("dialing the SMTP listener at %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)

	// expect reads one reply and fails on an unexpected status, so a listener that answers the dialogue
	// wrongly is reported as that rather than as a mysterious timeout later.
	expect := func(want string) string {
		t.Helper()
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			t.Fatalf("reading the reply after %q: %v", want, rerr)
		}
		if !strings.HasPrefix(line, want) {
			t.Fatalf("SMTP reply %q, want a %s", strings.TrimSpace(line), want)
		}
		return line
	}
	send := func(format string, a ...any) {
		t.Helper()
		if _, werr := fmt.Fprintf(conn, format+"\r\n", a...); werr != nil {
			t.Fatalf("writing %q: %v", format, werr)
		}
	}

	expect("220")
	send("EHLO client.example")
	// EHLO may answer with a multi-line 250; read until the last line (a space rather than a hyphen
	// after the code). Treating the first line as the whole reply leaves the rest in the buffer and
	// every later assertion reads the wrong line.
	for {
		line := expect("250")
		if len(line) > 3 && line[3] == ' ' {
			break
		}
	}
	send("MAIL FROM:<%s>", from)
	expect("250")
	send("RCPT TO:<%s>", to)
	expect("250")
	send("DATA")
	expect("354")
	send("Subject: quarterly export\r\n\r\n%s\r\n.", body)
	expect("250")
	send("QUIT")
}

// TestAnSmtpMessageIsCapturedClassifiedAndAudited.
//
// The sensitive value is a CHECKSUM-VALID CPF. That is what makes this a test of the content path
// rather than of the parser: the detector validates check digits, so a decision to alert can only come
// from the worker having actually classified the body.
func TestAnSmtpMessageIsCapturedClassifiedAndAudited(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(t.TempDir(), "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_SMTP_LISTEN=" + addr,
	})
	eng.WaitForOutput("SMTP capture connector ENABLED", 90*time.Second)

	// THE LIMITS ARE ANNOUNCED. An operator who mistakes a capture listener for an MTA loses mail, and
	// one who expects STARTTLS clients to be inspected gets a channel that silently sees nothing. Both
	// are late, expensive discoveries, so the startup line has to make them early ones.
	for _, want := range []string{"NOT an MTA", "STARTTLS"} {
		if !contains(eng.Output(), want) {
			t.Errorf("the SMTP startup line does not state %q, so a limit that surfaces as lost mail or "+
				"as an inert channel is left in the documentation:\n%s", want, eng.Output())
		}
	}
	waitTCP(t, addr, 60*time.Second)

	pool := openPool(t, stack.DSN)
	alerts := func() int {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n)
		return n
	}
	entries := func() int {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n)
		return n
	}

	// 1. AN ORDINARY MESSAGE FIRST. Without it, "the sensitive message alerted" is satisfied by an
	// engine that alerts on every email, which is an unusable channel rather than a DLP control — and
	// it also proves the listener is ingesting, so the negative below means something.
	before := entries()
	smtpDeliver(t, addr, "alice@corp.example", "bob@partner.example",
		"Lunch is at one. Nothing of interest in this message.")
	Eventually(t, 90*time.Second, "the ordinary message to reach the ledger", func() bool {
		return entries() > before
	})
	if n := alerts(); n != 0 {
		t.Errorf("an ORDINARY email produced %d alert(s). A mail channel that alerts on everything is "+
			"one operators turn off\n%s", n, eng.Output())
	}

	// 2. A MESSAGE CARRYING A CHECKSUM-VALID CPF must ALERT — the body reached the worker, was
	// classified, and the classification reached a decision.
	baseline := alerts()
	smtpDeliver(t, addr, "alice@corp.example", "exfil@partner.example",
		"name,cpf\nalice,111.444.777-35\n")
	Eventually(t, 90*time.Second, "the sensitive message to raise an alert", func() bool {
		return alerts() > baseline
	})

	// 3. AND THE BODY DOES NOT REACH THE LEDGER. The message text is exactly what must not be copied
	// into the longest-retained store in the system (D10/D29) — an email body in the audit trail makes
	// the evidence the disclosure.
	assertLedgerCarriesNone(t, stack, "111.444.777-35", "11144477735", "alice@corp.example")
}
