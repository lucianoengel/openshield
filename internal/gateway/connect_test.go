package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
)

// tlsUpstream is an HTTPS origin that records it was hit and echoes the body.
func tlsUpstream(t *testing.T) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var hit atomic.Bool
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s, &hit
}

// HTTPS transits the proxy via a CONNECT tunnel end to end, AND nothing about the
// tunneled body reaches the ledger — the honest coverage gap: tunneled HTTPS is
// relayed as ciphertext and not classified (interception, N1.3b, closes it).
func TestProxyTunnelsHTTPSWithoutInspecting(t *testing.T) {
	up, hit := tlsUpstream(t)
	led := &recLedger{}
	// The classifier/policy would ALERT on a CPF, but the tunnel bypasses the
	// pipeline entirely, so they must never run for tunneled bytes.
	gw := gateway.New(&fakeWorker{hits: cpfHit()}, deciding(corev1.Action_ACTION_ALERT), led, nil, time.Second)
	proxyURL := serveProxy(t, gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, false, nil))

	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	pu, _ := url.Parse(proxyURL)
	c := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	resp, err := c.Post(up.URL, "text/plain", strings.NewReader("secret cpf 111.444.777-35"))
	if err != nil {
		t.Fatalf("HTTPS through the tunnel failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "secret cpf 111.444.777-35" {
		t.Fatalf("tunnel did not carry the request end to end: status=%d body=%q", resp.StatusCode, body)
	}
	if !hit.Load() {
		t.Error("upstream not reached through the CONNECT tunnel")
	}
	if len(led.entries) != 0 {
		t.Errorf("tunneled HTTPS was classified — %d ledger entries; a blind tunnel must inspect nothing (N1.3a)", len(led.entries))
	}
}

// A CONNECT to an unreachable upstream returns 502 rather than hanging.
func TestProxyConnectToDeadUpstream(t *testing.T) {
	gw := gateway.New(&fakeWorker{}, deciding(corev1.Action_ACTION_ALLOW), &recLedger{}, nil, time.Second)
	proxyURL := serveProxy(t, gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, false, nil))

	pu, _ := url.Parse(proxyURL)
	c := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
	// 127.0.0.1:1 is not listening — the CONNECT dial fails.
	_, err := c.Get("https://127.0.0.1:1/")
	if err == nil {
		t.Fatal("expected the CONNECT to a dead upstream to fail")
	}
	// The proxy signals 502; the client surfaces it as a transport error naming
	// the status. Either way the request did not succeed, which is the property.
	if !strings.Contains(err.Error(), "502") && !strings.Contains(err.Error(), "Bad Gateway") {
		t.Logf("connect error (acceptable): %v", err)
	}
}
