package gateway_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
)

// NIPS-10 — HTTP/2 INTERCEPTION.
//
// Forcing http/1.1 in the interception ALPN looked harmless: a client that offers both simply downgrades
// and is inspected exactly as before. The clients that DO NOT offer both are the problem. A gRPC client
// advertises "h2" alone, so selecting http/1.1 fails its handshake with no application protocol — the
// flow is not inspected, it is BROKEN. A deployment then adds the host to the do-not-intercept list, and
// gRPC becomes a channel this product has excluded itself from, permanently and quietly.

// h2OnlyClient is a client that offers ONLY h2 — the gRPC shape. It reaches the origin through the
// proxy's CONNECT by hand, because that is the only way to control the ALPN list the way a gRPC client
// controls it; an http.Transport negotiates on its own and would silently downgrade, which is precisely
// the behaviour that hid this gap.
func h2OnlyClient(t *testing.T, proxyURL string, caPool *x509.CertPool) *http.Client {
	t.Helper()
	pu, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http2.Transport{
		DialTLSContext: func(_ context.Context, _, addr string, _ *tls.Config) (net.Conn, error) {
			raw, derr := net.DialTimeout("tcp", pu.Host, 10*time.Second)
			if derr != nil {
				return nil, derr
			}
			if _, werr := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); werr != nil {
				raw.Close()
				return nil, werr
			}
			br := bufio.NewReader(raw)
			status, rerr := br.ReadString('\n')
			if rerr != nil {
				raw.Close()
				return nil, rerr
			}
			if !strings.Contains(status, "200") {
				raw.Close()
				return nil, fmt.Errorf("proxy refused the CONNECT: %s", strings.TrimSpace(status))
			}
			for { // drain the CONNECT response headers
				line, lerr := br.ReadString('\n')
				if lerr != nil || line == "\r\n" || line == "\n" {
					break
				}
			}
			host, _, _ := net.SplitHostPort(addr)
			tc := tls.Client(raw, &tls.Config{
				RootCAs:    caPool,
				ServerName: host,
				// ONLY h2. This is the assertion, expressed as a fixture: a gateway that does not
				// offer it cannot complete this handshake at all.
				NextProtos: []string{"h2"},
				MinVersion: tls.VersionTLS12,
			})
			if herr := tc.HandshakeContext(context.Background()); herr != nil {
				raw.Close()
				return nil, herr
			}
			return tc, nil
		},
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}

// h2Setup mirrors interceptSetup but returns the pieces an h2 client needs.
func h2Setup(t *testing.T, action corev1.Action, enforce bool) (*http.Client, *httptest.Server, *recLedger) {
	t.Helper()
	up, _ := tlsUpstream(t)

	certPEM, keyPEM := interceptionCA(t)
	minter, err := gateway.NewCertMinter(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	led := &recLedger{}
	gw := gateway.New(&fakeWorker{hits: cpfHit()}, deciding(action), led, nil, time.Second)
	proxy := gateway.NewProxy(gw, gateway.NewTable(), nil, "https://coach.example/why", 0, enforce, nil)

	originPool := x509.NewCertPool()
	originPool.AddCert(up.Certificate())
	proxy.EnableInterception(minter,
		nil, &http.Transport{TLSClientConfig: &tls.Config{RootCAs: originPool, MinVersion: tls.VersionTLS12}})

	proxyURL := serveProxy(t, proxy)
	caPool := x509.NewCertPool()
	cb, _ := pem.Decode(certPEM)
	caCert, _ := x509.ParseCertificate(cb.Bytes)
	caPool.AddCert(caCert)
	return h2OnlyClient(t, proxyURL, caPool), up, led
}

// THE HEADLINE: a client that speaks ONLY h2 is intercepted and inspected, not broken.
//
// Mutation (NextProtos back to just http/1.1): the TLS handshake fails with "no application protocol"
// and the request never happens → FAIL.
func TestAnH2OnlyClientIsInterceptedRatherThanBroken(t *testing.T) {
	c, up, led := h2Setup(t, corev1.Action_ACTION_ALERT, false)

	resp, err := c.Post(up.URL, "text/plain", strings.NewReader("secret cpf 111.444.777-35"))
	if err != nil {
		t.Fatalf("an h2-only client could not transit the intercepting proxy: %v\n"+
			"That is not an inspected flow, it is a broken one — a deployment's only recourse is to "+
			"add the host to the do-not-intercept list, at which point gRPC becomes a channel this "+
			"product has excluded itself from", err)
	}
	defer resp.Body.Close()

	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("the response came back over %q, want HTTP/2.0 — the client offered nothing else, so "+
			"anything but h2 means the fixture is not testing what it claims", resp.Proto)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "secret cpf 111.444.777-35" {
		t.Fatalf("the h2 request did not reach the origin intact: status=%d body=%q", resp.StatusCode, body)
	}

	// AND IT WAS INSPECTED. Carrying the request is half the job; a proxy that relays h2 without
	// classifying it has converted a coverage gap into a coverage gap with extra steps.
	if len(led.entries) == 0 {
		t.Fatal("the h2 request produced no audit entry — the DLP pipeline did not run on it, so h2 " +
			"traffic transits inspected-in-name-only")
	}
}

// AND THE POLICY BINDS OVER h2. A block decided on an h2 request must actually refuse it, or h2 is a way
// around every rule the h1 path enforces — which is worse than not intercepting it at all, because the
// deployment believes it is covered.
//
// Mutation (serve h2 with a handler that bypasses p.serve): the request reaches the origin → FAIL.
func TestABlockDecisionBindsOverHTTP2(t *testing.T) {
	c, up, _ := h2Setup(t, corev1.Action_ACTION_BLOCK, true)

	resp, err := c.Post(up.URL, "text/plain", strings.NewReader("secret cpf 111.444.777-35"))
	if err != nil {
		t.Fatalf("the blocked h2 request errored rather than being refused: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a BLOCK decision returned %d over h2 — the same request over HTTP/1.1 is refused, so "+
			"h2 would be a way around every rule the h1 path enforces, in a deployment that believes "+
			"it is covered", resp.StatusCode)
	}
}

// A CLIENT THAT PREFERS h1 STILL GETS h1. Offering h2 must not force it on anybody: the existing
// interception path is unchanged for every client that was already working.
func TestAnHTTP1ClientIsUnaffectedByTheOfferOfH2(t *testing.T) {
	c, up, _, led := interceptSetup(t, corev1.Action_ACTION_ALERT, false, nil)

	resp, err := c.Post(up.URL, "text/plain", strings.NewReader("secret cpf 111.444.777-35"))
	if err != nil {
		t.Fatalf("an HTTP/1.1 client broke when h2 was offered: %v", err)
	}
	defer resp.Body.Close()
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("an ordinary client was moved to %q — offering a protocol is not the same as imposing "+
			"one, and a silent upgrade changes the framing every existing deployment was tested against",
			resp.Proto)
	}
	if len(led.entries) == 0 {
		t.Fatal("the HTTP/1.1 path stopped classifying")
	}
}
