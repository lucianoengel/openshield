package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
)

// interceptSetup builds: a TLS origin the gateway trusts, a proxy with interception
// enabled (in-test CA), and a client that trusts the interception CA and uses the
// proxy. It returns the client, the origin, its hit flag, and the ledger.
func interceptSetup(t *testing.T, policyAction corev1.Action, enforce bool, noIntercept []string) (*http.Client, *httptest.Server, *atomicBoolHolder, *recLedger) {
	t.Helper()
	up, hit := tlsUpstream(t)

	certPEM, keyPEM := interceptionCA(t)
	minter, err := gateway.NewCertMinter(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	led := &recLedger{}
	gw := gateway.New(&fakeWorker{hits: cpfHit()}, deciding(policyAction), led, nil, time.Second)
	proxy := gateway.NewProxy(gw, gateway.NewTable(), nil, "https://coach.example/why", 0, enforce, nil)

	// The gateway's origin transport must trust the httptest origin's cert.
	originPool := x509.NewCertPool()
	originPool.AddCert(up.Certificate())
	originRT := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: originPool}}
	proxy.EnableInterception(minter, noIntercept, originRT)

	proxyURL := serveProxy(t, proxy)

	// The client trusts the INTERCEPTION CA (so the minted leaf is accepted) and
	// uses the proxy.
	caPool := x509.NewCertPool()
	cb, _ := pem.Decode(certPEM)
	caCert, _ := x509.ParseCertificate(cb.Bytes)
	caPool.AddCert(caCert)
	pu, _ := url.Parse(proxyURL)
	c := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}
	return c, up, &atomicBoolHolder{hit}, led
}

// The D74 coverage gap CLOSED: an intercepted HTTPS body carrying a CPF is
// classified (a ledger entry appears) and forwarded to the origin, with the minted
// leaf trusted by the client.
func TestInterceptClassifiesAndForwardsHTTPS(t *testing.T) {
	c, up, hit, led := interceptSetup(t, corev1.Action_ACTION_ALERT, false, nil)

	resp, err := c.Post(up.URL, "text/plain", strings.NewReader("secret cpf 111.444.777-35"))
	if err != nil {
		t.Fatalf("intercepted HTTPS failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "secret cpf 111.444.777-35" {
		t.Fatalf("intercept did not carry the request end to end: status=%d body=%q", resp.StatusCode, body)
	}
	if !hit.Load() {
		t.Error("origin not reached — an allowed intercepted request must be re-forwarded")
	}
	if len(led.entries) == 0 {
		t.Error("intercepted HTTPS body was NOT classified — the D74 coverage gap is not closed")
	}
	// An inspected flow records its Decision, NOT a tunnel entry — the two paths
	// are distinct in the ledger (D78).
	for _, e := range led.entries {
		if e.OutcomeKind == "tunneled" {
			t.Error("an intercepted flow recorded a 'tunneled' entry — inspected flows must record a decision, not a tunnel")
		}
	}
}

// A BLOCK verdict on the inner intercepted request is applied: 403, origin never hit.
func TestInterceptBlocksInnerRequest(t *testing.T) {
	c, up, hit, _ := interceptSetup(t, corev1.Action_ACTION_BLOCK, true, nil)

	resp, err := c.Post(up.URL, "text/plain", strings.NewReader("cpf 111.444.777-35"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a blocked intercepted request", resp.StatusCode)
	}
	if hit.Load() {
		t.Error("origin WAS reached despite BLOCK on the intercepted request")
	}
}

// A host on the do-not-intercept list is tunneled blind even with interception on:
// nothing is classified (D74 behaviour preserved for excluded hosts).
func TestDoNotInterceptTunnelsExcludedHost(t *testing.T) {
	// Exclude the origin's host, so it is tunneled rather than intercepted.
	up, hit := tlsUpstream(t)
	origin, _ := url.Parse(up.URL)
	certPEM, keyPEM := interceptionCA(t)
	minter, _ := gateway.NewCertMinter(certPEM, keyPEM)
	led := &recLedger{}
	gw := gateway.New(&fakeWorker{hits: cpfHit()}, deciding(corev1.Action_ACTION_ALERT), led, nil, time.Second)
	proxy := gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, false, nil)
	proxy.EnableInterception(minter, []string{origin.Hostname()}, nil)
	proxyURL := serveProxy(t, proxy)

	// The client trusts the ORIGIN's own cert (it is tunneled, so it sees the real
	// origin cert, not a minted one).
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	pu, _ := url.Parse(proxyURL)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}

	resp, err := c.Post(up.URL, "text/plain", strings.NewReader("cpf 111.444.777-35"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !hit.Load() {
		t.Error("origin not reached through the tunnel")
	}
	// The do-not-intercept host is tunneled blind but now AUDITED as metadata
	// (D78): one "tunneled" entry with reason do-not-intercept, no classification.
	if len(led.entries) != 1 {
		t.Fatalf("do-not-intercept host recorded %d entries, want exactly 1 tunnel entry (D78)", len(led.entries))
	}
	e := led.entries[0]
	if e.OutcomeKind != "tunneled" || e.Decision != nil {
		t.Errorf("entry = kind %q decision %v, want a decision-less 'tunneled' outcome (not classified)", e.OutcomeKind, e.Decision)
	}
	if !strings.Contains(e.OutcomeStage, "do-not-intercept") {
		t.Errorf("tunnel entry stage = %q, want reason do-not-intercept", e.OutcomeStage)
	}
}

// atomicBoolHolder adapts the *atomic.Bool returned by tlsUpstream to a Load()-only
// view for the shared setup helper.
type atomicBoolHolder struct{ b interface{ Load() bool } }

func (h *atomicBoolHolder) Load() bool { return h.b.Load() }
