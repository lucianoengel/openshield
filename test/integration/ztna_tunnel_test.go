//go:build integration

package integration

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE ACCESS BROKER REACHING A NON-HTTP SERVICE (D427), IN THE SHIPPED BINARY.
//
// The topology has always claimed users reach "web apps, file servers and databases" through the gateway.
// The package tests prove the CONNECT handler; what only a real process proves is that a `tcp://` entry
// in OPENSHIELD_ACCESS_CATALOG survives config parsing, reaches the catalogue, and is dialled — the
// wiring, which is where a feature that works everywhere else quietly does nothing.
//
// The whole scenario runs against a plain TCP echo service, because that is what a database is from the
// gateway's point of view: bytes it must broker and cannot read.

// echoService is a plain TCP service — the thing a CONNECT exists to reach.
func echoService(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					if _, werr := fmt.Fprintf(c, "echo:%s", line); werr != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// TestTheBrokerTunnelsToANonHTTPService (D427).
//
// Mutation (drop the tcp:// branch from ParseCatalog, or the CONNECT branch from ServeHTTP): the
// authorized client gets a non-200 to its CONNECT, or the byte round trip never completes → FAIL.
func TestTheBrokerTunnelsToANonHTTPService(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	db := echoService(t)
	work := t.TempDir()

	policyPath := filepath.Join(work, "access.rego")
	if err := os.WriteFile(policyPath, []byte(accessPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	m := p.serverMaterial(t)
	addr := "127.0.0.1:" + freePort(t)

	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_ACCESS_MODE=1",
		"OPENSHIELD_ACCESS_LISTEN=" + addr,
		"OPENSHIELD_ACCESS_CLIENT_CA=" + p.caPEM,
		"OPENSHIELD_ACCESS_SERVER_CERT=" + m.Cert,
		"OPENSHIELD_ACCESS_SERVER_KEY=" + m.Key,
		"OPENSHIELD_ACCESS_POLICY=" + policyPath,
		// A tcp:// entry beside an http:// one, so the two kinds coexist in one catalogue exactly as a
		// deployment fronting both a web app and a database has them.
		"OPENSHIELD_ACCESS_CATALOG=db=tcp://" + db + ",wiki=http://127.0.0.1:1",
	})
	gw.WaitForOutput("ZERO-TRUST ACCESS MODE", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)

	caPEM, err := os.ReadFile(p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA did not parse")
	}

	// connect speaks the protocol by hand: an http.Client that handles CONNECT transparently would hide
	// the thing under test — whether the gateway replies 200 and then hands the connection over as an
	// unframed byte pipe.
	connect := func(cert tls.Certificate, service string) (net.Conn, *bufio.Reader, string) {
		t.Helper()
		conn, derr := tls.Dial("tcp", addr, &tls.Config{
			Certificates: []tls.Certificate{cert}, RootCAs: pool,
			ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
		})
		if derr != nil {
			t.Fatalf("dialling the broker: %v", derr)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		// Port 5432 deliberately: nothing listens there. If the gateway honoured the CLIENT's address
		// instead of the catalogue's, this could not connect — so the round trip below also proves the
		// allow-list constrains the address and not only the name.
		if _, werr := fmt.Fprintf(conn, "CONNECT %s:5432 HTTP/1.1\r\nHost: %s:5432\r\n\r\n",
			service, service); werr != nil {
			t.Fatal(werr)
		}
		br := bufio.NewReader(conn)
		status, rerr := br.ReadString('\n')
		if rerr != nil {
			t.Fatalf("reading the CONNECT reply: %v", rerr)
		}
		for {
			line, lerr := br.ReadString('\n')
			if lerr != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		return conn, br, status
	}

	// 1. THE AUTHORIZED IDENTITY gets a byte pipe to the database.
	finance := p.leafCert(t, "client", "finance-app", "--group", "finance")
	conn, br, status := connect(finance, "db")
	if len(status) < 12 || status[9:12] != "200" {
		t.Fatalf("CONNECT reply = %q, want 200 — without this a database cannot be reached through the "+
			"gate at all, which in practice means a VPN beside it\n%s", status, gw.Output())
	}
	if _, err := conn.Write([]byte("SELECT 1\n")); err != nil {
		t.Fatal(err)
	}
	got, err := br.ReadString('\n')
	if err != nil || got != "echo:SELECT 1\n" {
		t.Fatalf("the tunnel returned %q (%v) — a gateway that replies 'Connection Established' and "+
			"splices nothing is indistinguishable from a working one until somebody tries to use it\n%s",
			got, err, gw.Output())
	}

	// 2. AN UNAUTHORIZED IDENTITY gets no tunnel. A tunnel that skipped authorization would bypass every
	// per-service rule the HTTP path enforces.
	sales := p.leafCert(t, "client", "sales-app", "--group", "sales")
	if _, _, s := connect(sales, "db"); len(s) >= 12 && s[9:12] == "200" {
		t.Fatalf("an UNAUTHORIZED identity was given a tunnel (%q)\n%s", s, gw.Output())
	}

	// 3. A CATALOGUED HTTP SERVICE REFUSES A CONNECT. Otherwise every web app in the catalogue would
	// double as a TCP pivot to whatever its upstream is listening on.
	if _, _, s := connect(finance, "wiki"); len(s) >= 12 && s[9:12] == "200" {
		t.Fatalf("a CONNECT at an HTTP-catalogued service was admitted (%q)\n%s", s, gw.Output())
	}

	// 4. AN UNCATALOGUED HOST is unreachable — the gateway is an allow-list, not an open relay.
	if _, _, s := connect(finance, "nowhere"); len(s) >= 12 && s[9:12] == "200" {
		t.Fatalf("an UNCATALOGUED host was tunnelled to (%q)\n%s", s, gw.Output())
	}
}

// TestAKnownBadClientFingerprintDropsABlindTunnel (D429).
//
// A blind CONNECT tunnel is the one flow this gateway explicitly cannot inspect — the bytes are
// ciphertext by design (D74/D78). Everything else the IOC engine matches on describes the destination,
// and here the destination is often the least informative thing available. The CLIENT STACK is what
// survives that, so a tunnel the product has already conceded it cannot read is exactly where a
// fingerprint earns its place.
//
// THE FINGERPRINT IS NOT HARD-CODED. A literal digest in a test file rots the day Go changes its cipher
// list, and would then fail as "JA3 is broken" rather than "the fixture is stale". It is computed by the
// SHIPPED gateway from the same client's handshake, read out of its own log on a first pass, and then
// fed back as an indicator on a second — which also proves the value the gateway derives is the value an
// operator would list.
func TestAKnownBadClientFingerprintDropsABlindTunnel(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	origin := startTLSOrigin(t)

	// PASS 1: no feed. The tunnel is allowed and the gateway logs the fingerprint it computed.
	proxy := "127.0.0.1:" + freePort(t)
	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_LISTEN=" + proxy,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "gw-signer.state"),
	})
	waitTCP(t, proxy, 90*time.Second)

	if !tunnelHandshake(t, proxy, origin) {
		t.Fatalf("the tunnel did not carry a TLS handshake with no feed configured\n%s", gw.Output())
	}
	ja3 := fingerprintFromLog(t, gw)
	if ja3 == "" {
		t.Fatalf("the gateway logged no JA3 for a tunnelled TLS flow — a blind tunnel is the one place "+
			"the client stack is the only signal left, and computing nothing there is the feature "+
			"being absent where it matters most\n%s", gw.Output())
	}
	gw.Stop()

	// PASS 2: the SAME fingerprint is now an indicator, and the destination is on nothing.
	feed := filepath.Join(work, "ioc.feed")
	if err := os.WriteFile(feed, []byte("ja3 "+ja3+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	proxy2 := "127.0.0.1:" + freePort(t)
	gw2 := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_LISTEN=" + proxy2,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		// THE SAME SIGNER STATE as the first pass, not a fresh one. The ledger's hash chain is bound to
		// the signer that started it (T-017), so a second gateway on the same database with new keys
		// refuses to open the ledger — which would fail this scenario for a reason that has nothing to
		// do with fingerprints.
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "gw-signer.state"),
		"OPENSHIELD_IOC_FEED=" + feed,
	})
	waitTCP(t, proxy2, 90*time.Second)

	if tunnelHandshake(t, proxy2, origin) {
		t.Fatalf("a client whose fingerprint IS on the feed completed a TLS handshake through the "+
			"tunnel — the destination is listed nowhere, so this is the only axis that could have "+
			"caught it\n%s", gw2.Output())
	}
	gw2.WaitForOutput("tunnel DROPPED on a known-bad client fingerprint", 30*time.Second)

	// The block is auditable. A dropped tunnel with no record is indistinguishable from the origin
	// being down, which is the worst possible reading of a deliberate refusal.
	pool := openPool(t, stack.DSN)
	Eventually(t, 60*time.Second, "the blocked tunnel to be recorded in the ledger", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM audit_entries WHERE outcome_kind='tunnel-blocked'`).Scan(&n)
		return n > 0
	})
}

// startTLSOrigin is an HTTPS origin the proxy will tunnel to. Its certificate does not matter — the
// client never verifies it, because the handshake is the thing under test and it is deliberately allowed
// to fail on trust AFTER the ClientHello has been sent and fingerprinted.
func startTLSOrigin(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("origin"))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

// tunnelHandshake CONNECTs through the proxy and attempts a TLS handshake to the origin, reporting
// whether the handshake completed.
//
// A completed handshake is the assertion, not a 200 to the CONNECT: the gateway replies 200 before it
// fingerprints anything (the client sends its ClientHello only once it believes the tunnel is up), so
// the status line cannot distinguish an allowed tunnel from a blocked one. Whether the TLS session
// actually forms can.
func tunnelHandshake(t *testing.T, proxy, origin string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy, 10*time.Second)
	if err != nil {
		t.Fatalf("dialling the proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin, origin); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || len(status) < 12 || status[9:12] != "200" {
		return false
	}
	for {
		line, lerr := br.ReadString('\n')
		if lerr != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	tc := tls.Client(conn, &tls.Config{ServerName: "example.internal", InsecureSkipVerify: true}) //nolint:gosec // the origin is a throwaway httptest certificate; the HANDSHAKE reaching it is the assertion
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	return tc.Handshake() == nil
}

// fingerprintFromLog reads the ja3 the gateway logged for the tunnel it just carried.
func fingerprintFromLog(t *testing.T, gw *Process) string {
	t.Helper()
	gw.WaitForOutput("tunneling HTTPS", 30*time.Second)
	for _, line := range strings.Split(gw.Output(), "\n") {
		if !strings.Contains(line, "tunneling HTTPS") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(f, "ja3="); ok {
				return strings.Trim(v, `"`)
			}
		}
	}
	return ""
}
