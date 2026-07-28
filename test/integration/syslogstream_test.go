//go:build integration

package integration

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RELIABLE ESTATE-LOG INGEST (SIEM-4, D337): TCP and mutual TLS.
//
// The datagram listener cannot lose events VISIBLY. A datagram the kernel discards for want of receive
// buffer never reaches the process, so no counter the process keeps can see it — which is the silent gap
// the product forbids everywhere else (D31), on the one ingest path carrying somebody ELSE'S evidence.
//
// A stream gives delivery and backpressure. Mutual TLS gives something a datagram cannot: an
// ATTRIBUTABLE sender. Without it anything that can reach the port can inject events into a store
// operators are invited to treat as evidence, and fabricated evidence is a worse failure than lost
// evidence — which is why the certificate scenarios below matter more than the throughput ones.

const cefStreamLine = `<134>1 2026-07-28T10:00:00Z fw01 app - - - CEF:0|Vendor|StreamFirewall|1.0|100|Blocked|5|src=203.0.113.9`

// TestACefEventOverTcpIsStored.
//
// Asserted on the STORE. A listener that accepts a connection and discards what it reads is the quietest
// failure a SIEM has — the port is open, the device reports success, and the events are gone.
func TestACefEventOverTcpIsStored(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)
	setDynamic(t, stack, "OPENSHIELD_SYSLOG_TCP_LISTEN", addr)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("syslog STREAM ingest on", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dialing the stream listener: %v\n%s", err, srv.Output())
	}
	// BOTH FRAMINGS on one connection, because a sender may use either and requiring one is how a log
	// source ends up not onboarded.
	octet := fmt.Sprintf("%d %s", len(cefStreamLine), cefStreamLine)
	if _, err := fmt.Fprintf(conn, "%s\n%s", cefStreamLine, octet); err != nil {
		t.Fatal(err)
	}

	pool := openPool(t, stack.DSN)
	Eventually(t, 90*time.Second, "both framings to be STORED, not merely received", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM external_logs WHERE product = 'StreamFirewall'`).Scan(&n)
		return n >= 2
	})
	_ = conn.Close()

	// And the startup line is honest about what this transport does NOT give.
	if !contains(srv.Output(), "SENDER IS NOT AUTHENTICATED") {
		t.Errorf("the plaintext stream listener did not say that its sender is unauthenticated. An "+
			"operator pointing devices at it is entitled to know the store's contents are not "+
			"attributable\n%s", srv.Output())
	}
}

// TestOverTlsAnUnauthenticatedSenderIsRefused is the evidentiary claim.
//
// Three senders, and the two refusals are the point: encryption alone would protect a message in flight
// and leave the sender anonymous, which does not address injection. The assertion is on the STORE as
// well as the handshake — a refused handshake that somehow stored something would be the worst of both.
func TestOverTlsAnUnauthenticatedSenderIsRefused(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)
	setDynamic(t, stack, "OPENSHIELD_SYSLOG_TLS_LISTEN", addr)

	srv := Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	}, tlsEnv(m)...))
	srv.WaitForOutput("syslog STREAM ingest on", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)

	caPEM, err := os.ReadFile(m.CA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the test CA bundle parsed no certificates")
	}

	// send returns nil only if the server ACCEPTED the sender.
	//
	// IN TLS 1.3 THE SERVER'S VERDICT ON A CLIENT CERTIFICATE ARRIVES AFTER THE CLIENT'S HANDSHAKE
	// COMPLETES. The client sends its certificate in its last flight and proceeds; the server verifies
	// afterwards and, on failure, sends an alert. So `Dial` and `Handshake` both SUCCEED against a server
	// that is about to refuse you, and the refusal surfaces on the first READ. A test that checked only
	// the handshake would conclude the listener accepts anonymous senders — which is exactly what the
	// first version of this concluded, about correct code.
	//
	// A read TIMEOUT therefore means accepted (the server said nothing because it is waiting for more
	// syslog); an alert or EOF means refused.
	send := func(t *testing.T, conf *tls.Config, line string) error {
		t.Helper()
		conn, err := tls.Dial("tcp", addr, conf)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.Handshake(); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1)
		_, rerr := conn.Read(buf)
		if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
			return nil // the server is listening, not objecting
		}
		return rerr
	}

	// 1. NO CLIENT CERTIFICATE — refused at the handshake.
	const anonLine = `<134>1 2026-07-28T10:00:00Z rogue app - - - CEF:0|Rogue|Anonymous|1.0|1|Injected|9|src=10.0.0.1`
	if err := send(t, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, anonLine); err == nil {
		t.Error("a sender presenting NO client certificate completed the handshake. Anything that can " +
			"reach the port could then inject events into a store operators treat as evidence, and " +
			"fabricated evidence is worse than lost evidence")
	}

	// 2. AN UNTRUSTED CERTIFICATE — well-formed, issued by an authority this deployment does not trust.
	// Only the verification can tell it from a legitimate one, which is what makes this the isolating case.
	other := newPKI(t)
	om := other.serverMaterial(t)
	otherCert, err := tls.LoadX509KeyPair(om.Cert, om.Key)
	if err != nil {
		t.Fatal(err)
	}
	const forgedLine = `<134>1 2026-07-28T10:00:00Z rogue app - - - CEF:0|Rogue|Untrusted|1.0|1|Injected|9|src=10.0.0.2`
	err = send(t, &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{otherCert}, MinVersion: tls.VersionTLS13,
	}, forgedLine)
	if err == nil {
		t.Error("a sender with a certificate from an UNTRUSTED authority was accepted — the deployment " +
			"is verifying that a certificate exists rather than who signed it")
	}

	// 3. AN OPERATOR-ISSUED CERTIFICATE is accepted and its event stored. Without this the refusals
	// above are satisfied by a listener that refuses everyone, which is an outage rather than a control.
	legit := filepath.Join(p.dir, "sender")
	if err := os.MkdirAll(legit, 0o700); err != nil {
		t.Fatal(err)
	}
	if o, err := runCapture(t, "openshield-provision", nil, "cert",
		"--ca", filepath.Join(p.dir, "ca"), "--role", "operator", "--cn", "fw01",
		"--san", "127.0.0.1", "--out", legit); err != nil {
		t.Fatalf("issuing the sender certificate: %v\n%s", err, o)
	}
	senderCert, err := tls.LoadX509KeyPair(filepath.Join(legit, "cert.pem"), filepath.Join(legit, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := send(t, &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{senderCert}, MinVersion: tls.VersionTLS13,
	}, cefStreamLine); err != nil {
		t.Fatalf("a sender with an OPERATOR-ISSUED certificate was refused: %v\n%s", err, srv.Output())
	}

	db := openPool(t, stack.DSN)
	Eventually(t, 90*time.Second, "the authenticated sender's event to be stored", func() bool {
		var n int
		_ = db.QueryRow(Ctx(t),
			`SELECT count(*) FROM external_logs WHERE product = 'StreamFirewall'`).Scan(&n)
		return n > 0
	})

	// AND NOTHING FROM THE REFUSED SENDERS. A handshake failure that still stored a message would be
	// the worst of both outcomes: an unauthenticated event, indistinguishable from an authenticated one.
	var injected int
	if err := db.QueryRow(Ctx(t),
		`SELECT count(*) FROM external_logs WHERE product IN ('Anonymous','Untrusted')`).Scan(&injected); err != nil {
		t.Fatal(err)
	}
	if injected != 0 {
		t.Errorf("%d event(s) from refused senders were stored — the handshake refused them and something "+
			"ingested them anyway", injected)
	}
}
