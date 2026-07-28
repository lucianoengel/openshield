//go:build integration

package integration

import (
	"net"
	"strings"
	"testing"
	"time"
)

// THE DNS QUERY CONNECTOR END TO END (NIPS-3, OPENSHIELD_DNS_LISTEN).
//
// `internal/connectors/dns` measured at ZERO integration coverage, and driving it is how the gap this
// change closes was found: `dns.TunnelScore` was written, documented and unit-tested with NO CALLER, so
// a covert-channel detector had never scored a live query — while the engine's DNS source claimed in its
// own doc comment that tunnelling detection was live.
//
// This asserts on the AUDIT ROW rather than on a log line. A startup line has been wrong four times in
// this project, and "the connector is listening" is exactly the claim that stays true while nothing
// downstream happens.

// dnsTap sends a real DNS question for name to a UDP listener, the way a resolver would.
//
// Hand-built rather than via net.Resolver, because the connector never ANSWERS: it is fed a mirror of
// DNS traffic (a SPAN port, an eBPF tap), so a client that waits for a reply would block forever. This
// writes the datagram and moves on, which is also what a tap sees.
func dnsTap(t *testing.T, addr, name string) {
	t.Helper()
	msg := []byte{
		0xab, 0xcd, // id
		0x01, 0x00, // flags: standard query, recursion desired
		0x00, 0x01, // qdcount 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)            // root label
	msg = append(msg, 0x00, 0x01)      // qtype A
	msg = append(msg, 0x00, 0x01)      // qclass IN
	conn, err := net.Dial("udp", addr) // #nosec G102 -- test client to a loopback listener
	if err != nil {
		t.Fatalf("dialing the DNS connector at %s: %v", addr, err)
	}
	defer conn.Close()
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("sending the query: %v", err)
	}
}

// The tunnelled name: base32-looking data in a single long label, which is what an exfiltration channel
// produces and what TunnelScore is built to notice. The payload is a recognisable string so the ledger
// assertion below has something specific to look for.
const tunnelledName = "nbswy3dpo5xxe3denbswy3dpo5xxe3depfsgk3tunfxgs3dfnzsg4zi.exfil.example"

// TestALiveDnsQueryIsScoredAndOnlyTheTunnelledOneAlerts.
//
// BOTH HALVES, in one run against one engine, because "the tunnelling query alerted" is satisfied by a
// detector that alerts on every query — which is worse than one that alerts on none: an alert channel
// operators learn to ignore, on the noisiest event source in any network.
func TestALiveDnsQueryIsScoredAndOnlyTheTunnelledOneAlerts(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + t.TempDir() + "/signer.state",
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_DNS_LISTEN=" + addr,
	})
	eng.WaitForOutput("DNS connector ENABLED", 90*time.Second)

	// The startup line must state the threshold it is running with. A detector whose threshold cannot be
	// read back is one whose typo is undiagnosable — the failure the range check refuses statically and
	// this reports operationally.
	if !contains(eng.Output(), "tunnel_threshold") {
		t.Errorf("the DNS connector's startup line does not report its tunnelling threshold:\n%s",
			eng.Output())
	}

	pool := openPool(t, stack.DSN)
	alerts := func() int {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n)
		return n
	}
	decided := func() int {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n)
		return n
	}

	// 1. ORDINARY NAMES FIRST. Resent until they are demonstrably in the ledger — over UDP there is no
	// delivery signal, and "no alert" is satisfied by a listener that never received anything, which is
	// the vacuous version of this whole scenario.
	before := alerts()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range []string{"www.example.com", "api.github.com", "cdn.example.net"} {
			dnsTap(t, addr, n)
		}
		if decided() >= 3 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if decided() < 3 {
		t.Fatalf("ordinary DNS queries produced %d audit entries — the connector received nothing, so "+
			"nothing below is being tested\n%s", decided(), eng.Output())
	}
	if n := alerts(); n != before {
		t.Errorf("an ORDINARY DNS query ALERTED (%d -> %d). A tunnelling detector that fires on normal "+
			"resolution is an alert channel that has to be ignored, on the noisiest source in the "+
			"network\n%s", before, n, eng.Output())
	}

	// 2. THE TUNNELLED NAME must alert — the signal reaching a decision, which is the part that did not
	// exist before this change.
	baseline := alerts()
	Eventually(t, 90*time.Second, "the tunnelled query to raise an alert", func() bool {
		dnsTap(t, addr, tunnelledName)
		return alerts() > baseline
	})

	// AND THE REASON NAMES THE SIGNAL, so an investigator can tell this alert from a DLP hit.
	var reason string
	if err := pool.QueryRow(Ctx(t),
		`SELECT coalesce(reason,'') FROM audit_entries WHERE action = 2 ORDER BY sequence DESC LIMIT 1`).
		Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if !contains(reason, "NIPS-3") {
		t.Errorf("the alert's reason does not name the tunnelling rule (%q), so it is indistinguishable "+
			"from any other alert in the ledger", reason)
	}

	// 3. AND THE LEDGER CARRIES NO PART OF THE NAME.
	//
	// This matters more here than anywhere else in the product. In a DNS tunnel the exfiltrated data IS
	// the query name, so an audit trail that recorded it would republish the exfiltration it exists to
	// detect — into the system's most copied and longest-retained store. A detector whose evidence is the
	// disclosure is worse than no detector, because it also creates the record.
	assertLedgerCarriesNone(t, stack,
		tunnelledName,
		"nbswy3dpo5xxe3denbswy3dpo5xxe3depfsgk3tunfxgs3dfnzsg4zi",
		"exfil.example")
}
