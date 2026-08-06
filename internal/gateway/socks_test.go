package gateway_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway"
)

// ZT-12 — SOCKS5 THROUGH THE ACCESS BROKER.
//
// CONNECT reaches non-HTTP services from clients that speak HTTP proxying. SOCKS5 reaches the ones that
// do not, which is most desktop tooling: ssh's ProxyCommand, database clients, anything pointed at a
// system-wide proxy setting. Leaving it out meant those users had a VPN beside the gate.
//
// It was deferred for a real reason — SOCKS5 has nowhere to put a certificate or a JWT — and these tests
// are about the design that answers it: the DEVICE is the mutual-TLS certificate, and the USER is a
// short-lived ticket BOUND to that device.

// socksSetup starts a mutually-authenticated SOCKS listener in front of an echo service.
func socksSetup(t *testing.T, rego string) (addr string, ap *gateway.AccessProxy, ca *accessCA, backend string) {
	t.Helper()
	backend = echoTCP(t)
	ap, ca = tunnelProxy(t, rego, func(c *gateway.Catalog) { c.AddTCP("db", backend) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{ca.serverCert(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS12,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ap.ServeSOCKS(ctx, tlsLn) }()
	t.Cleanup(func() { _ = tlsLn.Close() })
	return ln.Addr().String(), ap, ca, backend
}

// socksDial performs the whole SOCKS5 conversation and returns the connection plus the reply code.
//
// Spoken by hand rather than with a SOCKS library, because the properties under test are the REFUSALS —
// which method is offered, which command is accepted, what a bad ticket gets back — and a library would
// paper over each of them with its own retry or its own error.
func socksDial(t *testing.T, addr string, cert tls.Certificate, ca *accessCA,
	ticket, target string, cmd byte) (net.Conn, byte) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: ca.pool,
		ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dialling the SOCKS listener: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Method negotiation: offer username/password.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatalf("reading the method selection: %v", err)
	}
	if sel[1] != 0x02 {
		return conn, 0xFF // the server refused the method; the caller asserts on that
	}

	// RFC 1929: username is ignored by the server, the ticket rides in the password.
	req := []byte{0x01, 0x04}
	req = append(req, "user"...)
	req = append(req, byte(len(ticket)))
	req = append(req, ticket...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("reading the auth reply: %v", err)
	}
	if authResp[1] != 0x00 {
		return conn, 0xFE // authentication refused
	}

	// The request. Port 5432 deliberately: nothing listens there, so a reply of success also proves the
	// CATALOGUE supplied the address rather than the client.
	r := []byte{0x05, cmd, 0x00, 0x03, byte(len(target))}
	r = append(r, target...)
	r = binary.BigEndian.AppendUint16(r, 5432)
	if _, err := conn.Write(r); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading the SOCKS reply: %v", err)
	}
	return conn, reply[1]
}

// THE HEADLINE: a device certificate plus a ticket bound to it gets a byte pipe to a catalogued service.
func TestADeviceAndItsTicketGetASocksTunnel(t *testing.T) {
	addr, ap, ca, _ := socksSetup(t, tunnelPolicyRego)
	store := &gateway.TicketStore{}
	ap.SetTicketStore(store)

	cert := ca.clientCert(t, "alice@corp", "finance")
	tok, err := store.Issue(certSubject(t, cert), "user:alice", "finance")
	if err != nil {
		t.Fatal(err)
	}

	conn, rep := socksDial(t, addr, cert, ca, tok, "db", 0x01)
	if rep != 0x00 {
		t.Fatalf("SOCKS reply = 0x%02x, want success — without this, tooling that speaks SOCKS and not "+
			"HTTP proxying has a VPN beside the gate, and a Zero-Trust gate with a VPN next to it is a "+
			"VPN", rep)
	}
	if _, err := conn.Write([]byte("SELECT 1\n")); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || got != "echo:SELECT 1\n" {
		t.Fatalf("the SOCKS tunnel returned %q (%v) — a reply of success followed by no bytes is "+
			"indistinguishable from a working tunnel until somebody uses it", got, err)
	}
}

// A TICKET IS USELESS ON ANOTHER DEVICE.
//
// This is the whole reason a ticket is safe to hand out. It is a bearer credential and bearer credentials
// get stolen; the binding to the certificate it was issued to is what makes the theft worthless.
//
// Mutation (drop the device comparison in Redeem): the stolen ticket works from another certificate → FAIL.
func TestATicketDoesNotWorkFromAnotherDevice(t *testing.T) {
	addr, ap, ca, _ := socksSetup(t, tunnelPolicyRego)
	store := &gateway.TicketStore{}
	ap.SetTicketStore(store)

	alice := ca.clientCert(t, "alice@corp", "finance")
	tok, err := store.Issue(certSubject(t, alice), "user:alice", "finance")
	if err != nil {
		t.Fatal(err)
	}
	// A DIFFERENT device, with a perfectly valid certificate of its own, presenting Alice's ticket.
	mallory := ca.clientCert(t, "mallory@corp", "finance")
	if _, rep := socksDial(t, addr, mallory, ca, tok, "db", 0x01); rep != 0xFE {
		t.Fatalf("a ticket issued to one device was redeemed by another (reply 0x%02x) — the binding "+
			"is the only thing that makes a bearer credential safe to hand out", rep)
	}
	assertCountedRefusal(t, ap, 0, "the ticket refusal")
}

// assertCountedRefusal asserts that a refusal the client has ALREADY READ is already in the counter.
//
// IT DOES NOT POLL, and that is the assertion. Waiting for the counter would only ever prove the count
// arrives eventually, which is not the property under test: these counters are the only trace a refusal
// leaves — the connection is closed and the client is gone — so a count made after the reply is one that
// nobody reacting to the refusal can rely on. Reading it once, immediately, is what "counted before it
// was answered" means from outside the process.
//
// This is also the assertion that went intermittently red in CI before the handler was fixed, and its
// weakness is worth stating: with the increment back after the write it catches the fault only
// SOMETIMES, because the window is microseconds wide. The guarantee therefore lives in the handler's
// ordering; this only witnesses it.
func assertCountedRefusal(t *testing.T, ap *gateway.AccessProxy, before int64, what string) {
	t.Helper()
	if got := ap.SOCKSRefused(); got <= before {
		t.Errorf("%s left the refusal count at %d (was %d) — the count is made BEFORE the reply is "+
			"written, so a client holding the refusal must already be counted; a rising refusal count "+
			"on a mutually-authenticated listener is somebody presenting tickets they do not hold",
			what, got, before)
	}
}

// AN EXPIRED TICKET IS REFUSED, and expiry is what keeps a credential from outliving the posture check
// and the risk score that justified it.
func TestAnExpiredTicketIsRefused(t *testing.T) {
	addr, ap, ca, _ := socksSetup(t, tunnelPolicyRego)
	now := time.Now()
	store := &gateway.TicketStore{TTL: time.Minute, Now: func() time.Time { return now }}
	ap.SetTicketStore(store)

	cert := ca.clientCert(t, "alice@corp", "finance")
	tok, err := store.Issue(certSubject(t, cert), "user:alice", "finance")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // the ticket's TTL has passed

	if _, rep := socksDial(t, addr, cert, ca, tok, "db", 0x01); rep != 0xFE {
		t.Fatalf("an EXPIRED ticket was redeemed (reply 0x%02x) — the alternative to expiry is a "+
			"credential that outlives the session, the posture check and the risk score behind it", rep)
	}
}

// WITHOUT A TICKET STORE, EVERYTHING IS REFUSED.
//
// A SOCKS proxy that authenticated only the device would be a weaker door into the same services the
// HTTP path guards with two credentials — and the weaker door is the one that gets used.
//
// Mutation (fall back to device-only authentication when no store is configured): the connection
// succeeds → FAIL.
func TestWithNoTicketStoreEveryConnectionIsRefused(t *testing.T) {
	addr, _, ca, _ := socksSetup(t, tunnelPolicyRego) // SetTicketStore deliberately not called
	cert := ca.clientCert(t, "alice@corp", "finance")

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: ca.pool,
		ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err == nil {
		t.Fatal("a SOCKS listener with NO ticket store answered the method negotiation — it would be " +
			"authenticating the device alone, a weaker door into the same services the HTTP path " +
			"guards with two credentials")
	}
}

// BIND AND UDP ASSOCIATE ARE REFUSED, with the protocol's own code.
//
// BIND asks the gateway to open a listening socket into the protected network on a client's say-so;
// UDP ASSOCIATE is a second data path with its own decision points. Both are real SOCKS features, both
// are absent, and a client is TOLD rather than left to time out.
//
// Mutation (treat every command as CONNECT): a BIND request opens a tunnel → FAIL.
func TestBindAndUDPAssociateAreRefused(t *testing.T) {
	addr, ap, ca, _ := socksSetup(t, tunnelPolicyRego)
	store := &gateway.TicketStore{}
	ap.SetTicketStore(store)
	cert := ca.clientCert(t, "alice@corp", "finance")
	tok, _ := store.Issue(certSubject(t, cert), "user:alice", "finance")

	for name, cmd := range map[string]byte{"BIND": 0x02, "UDP ASSOCIATE": 0x03} {
		c, cmd := name, cmd
		t.Run(c, func(t *testing.T) {
			before := ap.SOCKSRefused()
			if _, rep := socksDial(t, addr, cert, ca, tok, "db", cmd); rep != 0x07 {
				t.Fatalf("%s got reply 0x%02x, want 0x07 (command not supported) — BIND would be a "+
					"listening socket into the protected network on a client's say-so", c, rep)
			}
			// The SAME ordering rule as the ticket refusal: this is the class, not that one instance.
			assertCountedRefusal(t, ap, before, "the refused "+c)
		})
	}
}

// AN UNCATALOGUED TARGET IS REFUSED, and so is one catalogued as HTTP: the gateway is an allow-list, and
// the catalogue supplies the address the client never gets to choose.
func TestASocksTargetMustBeACataloguedTCPService(t *testing.T) {
	backend := echoTCP(t)
	ap, ca := tunnelProxy(t, tunnelPolicyRego, func(c *gateway.Catalog) {
		c.AddTCP("db", backend)
		c.Add("wiki", mustURL(t, "http://127.0.0.1:1"))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{ca.serverCert(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS12,
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ap.ServeSOCKS(ctx, tlsLn) }()
	t.Cleanup(func() { _ = tlsLn.Close() })

	store := &gateway.TicketStore{}
	ap.SetTicketStore(store)
	cert := ca.clientCert(t, "alice@corp", "finance")
	tok, _ := store.Issue(certSubject(t, cert), "user:alice", "finance")

	for _, target := range []string{"nowhere", "wiki"} {
		before := ap.SOCKSRefused()
		if _, rep := socksDial(t, ln.Addr().String(), cert, ca, tok, target, 0x01); rep == 0x00 {
			t.Fatalf("target %q was tunnelled to — the gateway is an allow-list of TCP services, and "+
				"an HTTP-catalogued one would double as a pivot to whatever its upstream listens on",
				target)
		}
		assertCountedRefusal(t, ap, before, "the refused target "+target)
	}
}

// AN UNAUTHORIZED USER IS REFUSED even with a valid ticket: the ticket authenticates, the POLICY
// authorizes, and conflating the two would make a ticket a grant.
func TestAValidTicketStillGoesThroughThePolicy(t *testing.T) {
	addr, ap, ca, _ := socksSetup(t, tunnelPolicyRego) // allows role "finance" only
	store := &gateway.TicketStore{}
	ap.SetTicketStore(store)

	cert := ca.clientCert(t, "mallory@corp", "contractor")
	tok, err := store.Issue(certSubject(t, cert), "user:mallory", "contractor")
	if err != nil {
		t.Fatal(err)
	}
	if _, rep := socksDial(t, addr, cert, ca, tok, "db", 0x01); rep == 0x00 {
		t.Fatal("a ticket for an UNAUTHORIZED role opened a tunnel — the ticket authenticates and the " +
			"policy authorizes, and conflating them makes a ticket a grant")
	}
}

// A CLIENT THAT WILL NOT AUTHENTICATE IS REFUSED, not fallen back to "no authentication".
//
// Mutation (offer methodNone when the client does not offer username/password): an unauthenticated
// client gets a working proxy into the protected network → FAIL.
func TestAClientOfferingNoAuthenticationIsRefused(t *testing.T) {
	addr, ap, ca, _ := socksSetup(t, tunnelPolicyRego)
	ap.SetTicketStore(&gateway.TicketStore{})
	cert := ca.clientCert(t, "alice@corp", "finance")

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: ca.pool,
		ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// Offer ONLY "no authentication".
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatalf("no method selection came back: %v", err)
	}
	if sel[1] != 0xFF {
		t.Fatalf("the server selected method 0x%02x for a client offering only 'no authentication' — "+
			"a SOCKS proxy into a protected network that accepts unauthenticated clients is an open "+
			"relay", sel[1])
	}
	// This refusal is written inside socksNegotiateMethod, which is why THAT function counts it: a
	// caller cannot put a count before a write it does not perform.
	assertCountedRefusal(t, ap, 0, "the refused method negotiation")
}

// mustURL parses a URL for the catalogue fixtures.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
