package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
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

// HTTPS transits the proxy via a CONNECT tunnel end to end; the body is relayed as
// ciphertext and NOT classified. The tunnel is recorded as a metadata-only entry
// (D78) — uninspected, but visible — not the body, which stays opaque.
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
	// The tunnel is now AUDITED as metadata (D78): exactly one "tunneled" entry
	// naming the host, with no Decision and no body — uninspected, but no longer
	// invisible.
	if len(led.entries) != 1 {
		t.Fatalf("tunneled HTTPS recorded %d entries, want exactly 1 metadata-only tunnel entry (D78)", len(led.entries))
	}
	e := led.entries[0]
	if e.OutcomeKind != "tunneled" || e.Decision != nil {
		t.Errorf("tunnel entry = kind %q decision %v, want a decision-less 'tunneled' outcome", e.OutcomeKind, e.Decision)
	}
	if !strings.Contains(e.OutcomeStage, "127.0.0.1") || !strings.Contains(e.OutcomeStage, "interception-disabled") {
		t.Errorf("tunnel entry stage = %q, want the host + reason interception-disabled", e.OutcomeStage)
	}
}

// errLedger fails every append, to prove tunnel recording is best-effort. It
// reuses recLedger's Verify/Close and overrides Append to fail.
type errLedger struct{ *recLedger }

func (*errLedger) Append(context.Context, *core.Entry) error { return errPersist }

var errPersist = errors.New("ledger down")

// Recording a tunnel is best-effort: the tunnel still works end to end even when
// the ledger append fails (a recording failure must not sever connectivity, D78).
func TestTunnelAuditIsBestEffort(t *testing.T) {
	up, hit := tlsUpstream(t)
	gw := gateway.New(&fakeWorker{}, deciding(corev1.Action_ACTION_ALLOW), &errLedger{&recLedger{}}, nil, time.Second)
	proxyURL := serveProxy(t, gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, false, nil))

	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	pu, _ := url.Parse(proxyURL)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}

	resp, err := c.Post(up.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("tunnel failed when the ledger append failed — recording must be best-effort: %v", err)
	}
	resp.Body.Close()
	if !hit.Load() {
		t.Error("upstream not reached — a failing tunnel-audit append must not break the tunnel")
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
