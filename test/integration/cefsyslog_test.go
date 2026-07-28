//go:build integration

package integration

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// THE LIVE CEF-OVER-SYSLOG LISTENER (SIEM-4, OPENSHIELD_CEF_SYSLOG_LISTEN).
//
// This is what makes OpenShield a SIEM over the estate rather than a store of its own telemetry: a
// firewall, a proxy, an EDR pointed at this port, and their events become searchable next to
// OpenShield's own.
//
// Coverage measurement is why these exist. Running the integration suite against binaries built with
// `-cover` showed `internal/connectors/syslog`, `rfc5424` and `cef` at ZERO — three packages the suite
// never reached, invisible to a settings audit because the directory-poller scenarios covered the
// SIEM-4 setting family without ever touching the listener that carries the same claim.
//
// The failure they guard against is the quietest one a SIEM has: a listener that accepts a connection,
// reads a line, and stores nothing. Nothing errors, the port is open, and the estate's logs go nowhere.

// sendSyslog sends lines to the listener exactly as a device would — over UDP.
//
// UDP, because that is what the listener binds (`net.ListenUDP`), and it is worth stating rather than
// discovering: syslog over UDP has no delivery guarantee and no backpressure, so a burst that outpaces
// the reader is dropped by the kernel with no error at either end. A test that sent once and asserted
// would be flaky for the same reason a real estate loses events — so these RESEND while waiting, and
// the assertions are on the store rather than on the send.
func sendSyslog(t *testing.T, addr string, lines ...string) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dialing the CEF listener at %s: %v", addr, err)
	}
	defer conn.Close()
	for _, l := range lines {
		if _, err := fmt.Fprintf(conn, "%s\n", l); err != nil {
			t.Fatalf("writing to the listener: %v", err)
		}
	}
}

// sendUntil resends a line until cond holds, because UDP gives no signal that anything arrived and the
// listener may not have bound yet when the first datagram goes out.
func sendUntil(t *testing.T, addr string, line string, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		sendSyslog(t, addr, line)
		for i := 0; i < 10; i++ {
			if cond() {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestTheCefSyslogListenerStoresWhatTheEstateSends.
//
// It asserts on the STORE, not on the listener being up. A port that accepts and discards is the exact
// shape of the defect: the deployment looks configured, the device reports success, and the events are
// gone. Only a row in `external_logs` distinguishes the two.
func TestTheCefSyslogListenerStoresWhatTheEstateSends(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)
	setDynamic(t, stack, "OPENSHIELD_CEF_SYSLOG_LISTEN", addr)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("CEF-over-syslog listener on", 90*time.Second)

	// A CEF event as a firewall emits it, wrapped in RFC 5424 as a real relay would.
	const cefLine = `<134>1 2026-07-28T10:00:00Z fw01 CEF - - - CEF:0|Vendor|Firewall|1.0|100|Blocked connection|5|src=203.0.113.9 dst=10.0.0.5 spt=44321 dpt=445`
	pool := openPool(t, stack.DSN)
	sendUntil(t, addr, cefLine, "the CEF event to be STORED, not merely received", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM external_logs WHERE product = 'Firewall'`).Scan(&n)
		return n > 0
	})

	// AND IT IS SEARCHABLE BY ITS FIELDS. A row that can only be found by its raw text is archival, not
	// a SIEM — the whole point of ingesting a third party's logs is hunting across sources.
	var name, sig string
	if err := pool.QueryRow(Ctx(t),
		`SELECT name, signature_id FROM external_logs WHERE product = 'Firewall' LIMIT 1`).
		Scan(&name, &sig); err != nil {
		t.Fatal(err)
	}
	if name == "" && sig == "" {
		t.Errorf("the CEF event stored no normalised name or signature (name=%q sig=%q). Storing the "+
			"line without its fields means an investigator can grep it and cannot correlate it", name, sig)
	}
}

// TestALineNeitherParserAcceptsIsCountedNotDropped.
//
// An estate sends malformed lines — a truncated relay, a device with its own dialect. Discarding them
// silently is how a SIEM comes to be trusted for completeness it does not have: nobody can tell "that
// device sent nothing" from "we could not read what it sent" (D31).
//
// THE ORDER MATTERS, for the reason it did for the CASB catalog. A warm-up line goes FIRST so the
// listener is demonstrably bound and ingesting — otherwise "the malformed line was not stored" is
// satisfied by a listener that never came up, which over UDP gives no other signal. Then the malformed
// lines, then a further good one to show the feed survived them.
func TestALineNeitherParserAcceptsIsCountedNotDropped(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)
	setDynamic(t, stack, "OPENSHIELD_CEF_SYSLOG_LISTEN", addr)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("CEF-over-syslog listener on", 90*time.Second)

	pool := openPool(t, stack.DSN)
	stored := func() int {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM external_logs`).Scan(&n)
		return n
	}
	before := stored()

	// A GOOD line first, so the listener is demonstrably bound and ingesting — otherwise "the bad line
	// was not stored" is satisfied by a listener that never came up. UDP gives no other signal.
	const warmup = `<134>1 2026-07-28T10:00:00Z fw01 CEF - - - CEF:0|Vendor|Warmup|1.0|1|Warm|1|src=10.0.0.1`
	sendUntil(t, addr, warmup, "the listener to be ingesting at all", func() bool { return stored() > before })
	baseline := stored()

	// Neither CEF nor RFC 5424 — the shape a half-configured device produces.
	for i := 0; i < 5; i++ {
		sendSyslog(t, addr, "this is not a syslog line at all", "|||malformed|||")
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(3 * time.Second)
	if n := stored(); n != baseline {
		t.Errorf("an unparseable line was STORED (%d -> %d). A line neither parser accepts must be "+
			"counted, not turned into a row that looks like an event", baseline, n)
	}

	// The listener must still be alive and still ingesting — a parser error that kills the connection
	// silently stops the estate's whole feed, which is worse than the bad line.
	const good = `<134>1 2026-07-28T10:00:00Z fw01 CEF - - - CEF:0|Vendor|Proxy|1.0|200|Allowed|3|src=10.0.0.9`
	sendUntil(t, addr, good, "a GOOD line after a malformed one to be ingested", func() bool {
		return stored() > baseline // baseline, not before: the warm-up already moved `before`
	})
}
