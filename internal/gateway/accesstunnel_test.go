package gateway_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/gateway/identity"
	"github.com/lucianoengel/openshield/internal/policy"
)

// ZT-9 — CONNECT TUNNELS THROUGH THE ACCESS BROKER (the INBOUND direction).
//
// The topology has always said users reach "web apps, file servers and databases" through the gateway.
// The broker spoke HTTP only, so two thirds of that was aspiration: a database or an SSH host could not
// be reached through the gate at all, which in practice means a VPN beside it — and a Zero-Trust gate
// with a VPN next to it is a VPN.
//
// Distinct from the egress CONNECT tunnel next door (D78, connect_test.go): that one is an internal
// client reaching the internet, decided on destination and failing OPEN. This is an authenticated device
// and user reaching a catalogued internal service, decided on identity and failing CLOSED.

// echoTCP is a plain TCP service — the thing a CONNECT exists to reach. It echoes with a prefix so a
// test can prove bytes made a ROUND TRIP rather than that a connection was merely accepted.
func echoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if _, err := fmt.Fprintf(c, "echo:%s", line); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// tunnelPolicyRego allows the finance role and denies everything else.
const tunnelPolicyRego = `package openshield
import rego.v1
allowed if { input.context.role == "finance" }
decision := {"action":"ALLOW","reason":"authorized","confidence":0.9} if { allowed }
decision := {"action":"BLOCK","reason":"not authorized","confidence":0.9} if { not allowed }`

// dialTunnel opens a mutually-authenticated TLS connection, sends a CONNECT for a named service, and
// returns the connection, a reader positioned at the first tunnel byte, and the status line.
//
// It speaks the protocol by hand rather than through http.Client on purpose: a client that transparently
// handles CONNECT would hide exactly what is under test — whether the gateway replies 200 and then hands
// the connection over as an unframed byte pipe.
func dialTunnel(t *testing.T, addr, host string, cert tls.Certificate, ca *accessCA) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: ca.pool, ServerName: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// The requested port is deliberately 5432 in every case; no backend in these tests listens there.
	// That is what makes "the gateway dials the CATALOGUED address" observable rather than assumed.
	if _, err := fmt.Fprintf(conn, "CONNECT %s:5432 HTTP/1.1\r\nHost: %s:5432\r\n\r\n", host, host); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the CONNECT reply: %v", err)
	}
	for { // drain headers so the caller's first read is tunnel payload
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, br, status
}

func tunnelProxy(t *testing.T, rego string, build func(*gateway.Catalog)) (*gateway.AccessProxy, *accessCA) {
	t.Helper()
	pol, err := policy.New(context.Background(), "tunnel", "1", rego)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	build(cat)
	return gateway.NewAccessProxy(gw, cat, 0, nil), newAccessCA(t)
}

// certSubject derives the pseudonymous subject the proxy will key on, from the same certificate the test
// connects with. Derived rather than hard-coded, so publishing risk under the wrong key cannot make a
// revocation test pass by accident.
func certSubject(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.FromClientCert(leaf)
	if err != nil {
		t.Fatal(err)
	}
	return id.Subject
}

// THE HEADLINE: an authorized identity gets a byte pipe to a non-HTTP internal service.
//
// The assertion is a ROUND TRIP, not a 200. A gateway that replies "Connection Established" and then
// splices nothing looks identical to a working one until somebody tries to use it.
func TestAnAuthorizedIdentityGetsAByteTunnelToATCPService(t *testing.T) {
	backend := echoTCP(t)
	ap, ca := tunnelProxy(t, tunnelPolicyRego, func(c *gateway.Catalog) { c.AddTCP("db", backend) })
	addr := serveAccessTLS(t, ap, ca)

	conn, br, status := dialTunnel(t, addr, "db", ca.clientCert(t, "alice@corp", "finance"), ca)
	if !hasStatus(status, "200") {
		t.Fatalf("CONNECT reply = %q, want 200 — without this a database or an SSH host cannot be "+
			"reached through the gate at all, which means a VPN beside it", status)
	}
	if _, err := conn.Write([]byte("SELECT 1\n")); err != nil {
		t.Fatal(err)
	}
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading through the tunnel: %v", err)
	}
	if got != "echo:SELECT 1\n" {
		t.Fatalf("tunnel returned %q, want the backend's echo — a gateway that replies 'Connection "+
			"Established' and splices nothing is indistinguishable from a working one until somebody "+
			"tries to use it", got)
	}
}

// AN UNAUTHORIZED IDENTITY IS REFUSED, before any tunnel exists.
//
// Mutation (skip the pipeline decision in serveConnect, or ignore its action): the unauthorized client
// gets a working tunnel → FAIL.
func TestAnUnauthorizedIdentityGetsNoTunnel(t *testing.T) {
	backend := echoTCP(t)
	ap, ca := tunnelProxy(t, tunnelPolicyRego, func(c *gateway.Catalog) { c.AddTCP("db", backend) })
	addr := serveAccessTLS(t, ap, ca)

	_, _, status := dialTunnel(t, addr, "db", ca.clientCert(t, "mallory@corp", "contractor"), ca)
	if hasStatus(status, "200") {
		t.Fatalf("an unauthorized identity was given a tunnel (%q) — a tunnel that skips authorization "+
			"bypasses every per-service rule the HTTP path enforces", status)
	}
	if ap.TunnelsRefused() < 1 {
		t.Errorf("TunnelsRefused = %d, want >=1 — a refused tunnel nobody counts is a probe nobody "+
			"can see", ap.TunnelsRefused())
	}
}

// AN UNCATALOGUED HOST IS UNREACHABLE, AND SO IS A CATALOGUED HTTP SERVICE.
//
// The second half is the one that matters. If a CONNECT could target an HTTP-catalogued service, every
// web app in the catalogue would double as a TCP pivot to whatever its upstream happens to be listening
// on — the gateway becomes an open relay into the protected network through its own allow-list.
//
// Mutation (drop the tcpAddr checks in ServeHTTP): the CONNECT to the web service is admitted → FAIL.
func TestATunnelCannotTargetAnUncataloguedOrHTTPService(t *testing.T) {
	backend := echoTCP(t)
	web, _ := accessUpstream(t)
	webURL, _ := url.Parse(web.URL)

	ap, ca := tunnelProxy(t, tunnelPolicyRego, func(c *gateway.Catalog) {
		c.AddTCP("db", backend)
		c.Add("wiki", webURL)
	})
	addr := serveAccessTLS(t, ap, ca)
	cert := ca.clientCert(t, "alice@corp", "finance")

	if _, _, status := dialTunnel(t, addr, "nowhere", cert, ca); !hasStatus(status, "404") {
		t.Fatalf("an UNCATALOGUED host got %q, want 404 — the gateway is an allow-list, not an open "+
			"relay", status)
	}
	// 405 SPECIFICALLY, not merely "not 200". Removing the tcpAddr guard lets the CONNECT through to
	// the tunnel path, where an HTTP service has no dial address and the dial fails with 502 — so a
	// "not 200" assertion passes against the unguarded code, by accident, and proves nothing. The
	// refusal has to be the one the guard makes.
	if _, _, status := dialTunnel(t, addr, "wiki", cert, ca); !hasStatus(status, "405") {
		t.Fatalf("a CONNECT at a catalogued HTTP service got %q, want 405 — it must be REFUSED as a "+
			"wrong-method request, not fall through to the tunnel path and fail by accident. Every web "+
			"app in the catalogue would otherwise double as a TCP pivot to whatever its upstream is "+
			"listening on, and a stray dial success would be an open relay", status)
	}

	// And the reverse: a plain GET at a tcp:// entry is refused rather than reverse-proxied at
	// something that does not speak HTTP.
	client := accessClient(cert, ca.pool)
	resp, err := client.Do(hostReq(t, addr, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("a GET at a tcp:// service returned %d, want 405 — reverse-proxying HTTP at something "+
			"that does not speak it is a refusal, not a fallback", resp.StatusCode)
	}
}

// THE CLIENT NAMES A SERVICE; THE GATEWAY CHOOSES THE ADDRESS.
//
// Every dialTunnel above asks for port 5432 and no backend listens there. If the requested address were
// honoured, the headline test could not connect at all — so that test already proves this, and this one
// states it as its own assertion because it is the security property rather than a detail of the fixture.
//
// Honouring the client's address would make the allow-list constrain the service NAME and leave the
// address free: an open relay wearing a catalogue.
func TestTheGatewayDialsTheCataloguedAddressNotTheRequestedOne(t *testing.T) {
	backend := echoTCP(t)
	_, backendPort, _ := net.SplitHostPort(backend)
	if backendPort == "5432" {
		t.Skip("the ephemeral backend landed on the requested port; this test cannot distinguish")
	}
	ap, ca := tunnelProxy(t, tunnelPolicyRego, func(c *gateway.Catalog) { c.AddTCP("db", backend) })
	addr := serveAccessTLS(t, ap, ca)

	conn, br, status := dialTunnel(t, addr, "db", ca.clientCert(t, "alice@corp", "finance"), ca)
	if !hasStatus(status, "200") {
		t.Fatalf("CONNECT reply = %q, want 200", status)
	}
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	got, err := br.ReadString('\n')
	if err != nil || got != "echo:ping\n" {
		t.Fatalf("read %q, %v — the tunnel did not reach the CATALOGUED address. The client asked for "+
			"port 5432 and the catalogue says %s; the catalogue must win, or the allow-list constrains "+
			"the host and nothing else", got, err, backendPort)
	}
}

// RE-AUTHORIZATION TEARS DOWN A LIVE TUNNEL WHEN ACCESS IS WITHDRAWN.
//
// This is what makes CONNECT defensible in a Zero-Trust product. Without it one CONNECT is a permanent
// grant: the subject's risk rises, their device falls out of compliance, and the session opened five
// minutes earlier carries on regardless. Continuous verification that stops at the handshake is not
// continuous.
//
// The verdict changes through PUBLISHED RISK — the same mechanism production uses (D89) — rather than a
// switch only a test can flip.
//
// Mutation (drop the re-check goroutine, or log the withdrawal without closing the connections): the
// read below returns the echo instead of an error → FAIL.
func TestARevokedIdentityLosesAnAlreadyEstablishedTunnel(t *testing.T) {
	backend := echoTCP(t)
	ap, ca := tunnelProxy(t, `package openshield
import rego.v1
risky if { input.context.risk_score > 0.8 }
decision := {"action":"BLOCK","reason":"risk","confidence":0.9} if { risky }
decision := {"action":"ALLOW","reason":"ok","confidence":0.9} if { not risky }`,
		func(c *gateway.Catalog) { c.AddTCP("db", backend) })

	risk := gateway.NewRiskStore()
	ap.SetRiskStore(risk)
	ap.SetTunnelRecheckInterval(100 * time.Millisecond)
	addr := serveAccessTLS(t, ap, ca)

	cert := ca.clientCert(t, "alice@corp", "finance")
	conn, br, status := dialTunnel(t, addr, "db", cert, ca)
	if !hasStatus(status, "200") {
		t.Fatalf("CONNECT reply = %q, want 200 before revocation", status)
	}
	if _, err := conn.Write([]byte("before\n")); err != nil {
		t.Fatal(err)
	}
	if got, err := br.ReadString('\n'); err != nil || got != "echo:before\n" {
		t.Fatalf("the tunnel did not work BEFORE revocation (%q, %v) — a test where nothing worked "+
			"would pass the assertion below for the wrong reason", got, err)
	}

	// The subject's risk rises while the gateway holds an already-authorized tunnel.
	risk.Set(certSubject(t, cert), 0.99)
	waitForCount(t, ap.TunnelsRevoked, 1)

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("after\n")); err != nil {
		return // a failed write is the same torn-down tunnel
	}
	if got, err := br.ReadString('\n'); err == nil {
		t.Fatalf("the tunnel still carried traffic (%q) after the subject's risk crossed the deny "+
			"threshold — one CONNECT would then be a permanent grant", got)
	}
}

// A FAILED RE-CHECK LEAVES THE TUNNEL UP.
//
// The access decision fails CLOSED at the door because admitting on an error is unrecoverable. Killing
// an already-authorized session because the control plane blinked is the opposite trade: a self-inflicted
// outage on a session that was authorized, and it would make every transient error a disconnection storm.
//
// Mutation (tear the tunnel down when the re-check errors): the tunnel dies and this FAILs.
func TestAFailedReAuthorizationDoesNotKillTheTunnel(t *testing.T) {
	backend := echoTCP(t)
	// A worker that ERRORS makes Process fail — the pipeline-unavailable case, mid-session.
	pol, err := policy.New(context.Background(), "tunnel", "1", tunnelPolicyRego)
	if err != nil {
		t.Fatal(err)
	}
	failing := &flakyWorker{}
	gw := gateway.New(failing, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	cat.AddTCP("db", backend)
	ap := gateway.NewAccessProxy(gw, cat, 0, nil)
	ap.SetTunnelRecheckInterval(50 * time.Millisecond)
	ca := newAccessCA(t)
	addr := serveAccessTLS(t, ap, ca)

	conn, br, status := dialTunnel(t, addr, "db", ca.clientCert(t, "alice@corp", "finance"), ca)
	if !hasStatus(status, "200") {
		t.Fatalf("CONNECT reply = %q, want 200", status)
	}
	failing.fail.Store(true) // every re-check from here on errors

	time.Sleep(300 * time.Millisecond) // several re-check ticks
	if _, err := conn.Write([]byte("still here\n")); err != nil {
		t.Fatalf("the tunnel was closed by a FAILED re-check (%v) — the door fails closed because "+
			"admitting on an error is unrecoverable; disconnecting an already-authorized session "+
			"because the pipeline blinked is a self-inflicted outage", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := br.ReadString('\n')
	if err != nil || got != "echo:still here\n" {
		t.Fatalf("the tunnel stopped carrying traffic after failed re-checks: %q, %v", got, err)
	}
}

func hasStatus(statusLine, code string) bool {
	return len(statusLine) >= 12 && statusLine[9:12] == code
}

func waitForCount(t *testing.T, read func() int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if read() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("counter never reached %d (got %d) — a tunnel torn down by continuous verification "+
		"happens on a connection nobody is watching, so the count is how anyone finds out", want, read())
}

// flakyWorker classifies fine until fail is set, then errors — so a test can make the pipeline
// unavailable MID-SESSION rather than only at connect time.
type flakyWorker struct{ fail atomic.Bool }

func (f *flakyWorker) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	if f.fail.Load() {
		return nil, errors.New("worker unavailable")
	}
	return &corev1.ClassifyResponse{RequestId: req.GetRequestId(), EventId: req.GetEventId()}, nil
}
