package gateway_test

import (
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
	"github.com/lucianoengel/openshield/internal/policy"
)

// upstream is a test origin server that records whether it was hit and echoes the
// request body — so a forwarded flow is observable end to end and a blocked flow
// is proven to never reach it.
func upstream(t *testing.T) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var hit atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s, &hit
}

// proxyClient is a real http.Client configured to send through the proxy server
// (absolute-URI proxy requests) — exercising real sockets on both hops.
func proxyClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
}

func serveProxy(t *testing.T, p *gateway.Proxy) string {
	t.Helper()
	s := httptest.NewServer(p)
	t.Cleanup(s.Close)
	return s.URL
}

// A clean flow is forwarded to the upstream and its response returned — real
// sockets, real proxy client, the default policy (ALLOW), enforcement enabled.
func TestProxyForwardsAllowed(t *testing.T) {
	up, hit := upstream(t)
	pol, err := policy.NewDefault(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	proxyURL := serveProxy(t, gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, true, nil))

	resp, err := proxyClient(t, proxyURL).Post(up.URL, "text/plain", strings.NewReader("hello clean"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello clean" {
		t.Fatalf("forward failed: status=%d body=%q", resp.StatusCode, body)
	}
	if !hit.Load() {
		t.Error("upstream was not reached — an allowed flow must be forwarded")
	}
}

// A BLOCK decision with enforcement enabled returns 403 and the upstream is never
// reached — the verdict applied to the live connection.
func TestProxyBlocksOnLiveConnection(t *testing.T) {
	up, hit := upstream(t)
	gw := gateway.New(&fakeWorker{hits: cpfHit()}, deciding(corev1.Action_ACTION_BLOCK), &recLedger{}, nil, time.Second)
	proxyURL := serveProxy(t, gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, true, nil))

	resp, err := proxyClient(t, proxyURL).Post(up.URL, "text/plain", strings.NewReader("cpf 111.444.777-35"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a blocked flow", resp.StatusCode)
	}
	if hit.Load() {
		t.Error("upstream WAS reached despite BLOCK — the flow was not blocked on the live connection")
	}
}

// A REDIRECT decision returns 302 to the coaching URL and the upstream is not hit.
func TestProxyRedirects(t *testing.T) {
	up, hit := upstream(t)
	gw := gateway.New(&fakeWorker{hits: cpfHit()}, deciding(corev1.Action_ACTION_REDIRECT), &recLedger{}, nil, time.Second)
	proxyURL := serveProxy(t, gateway.NewProxy(gw, gateway.NewTable(), nil, "https://coach.example/why", 0, true, nil))

	// Do not auto-follow the redirect — assert on the 302 itself.
	c := proxyClient(t, proxyURL)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Post(up.URL, "text/plain", strings.NewReader("cpf 111.444.777-35"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://coach.example/why" {
		t.Fatalf("status=%d location=%q, want 302 to the coaching URL", resp.StatusCode, resp.Header.Get("Location"))
	}
	if hit.Load() {
		t.Error("upstream WAS reached despite REDIRECT")
	}
}

// Observe-only (enforcement NOT enabled): a BLOCK decision still forwards, and the
// decision is recorded (D1).
func TestProxyObserveOnlyForwardsAndAudits(t *testing.T) {
	up, hit := upstream(t)
	led := &recLedger{}
	gw := gateway.New(&fakeWorker{hits: cpfHit()}, deciding(corev1.Action_ACTION_BLOCK), led, nil, time.Second)
	proxyURL := serveProxy(t, gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, false, nil))

	resp, err := proxyClient(t, proxyURL).Post(up.URL, "text/plain", strings.NewReader("cpf 111.444.777-35"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — observe-only must forward", resp.StatusCode)
	}
	if !hit.Load() {
		t.Error("upstream not reached — observe-only must forward even a BLOCK decision")
	}
	if len(led.entries) == 0 {
		t.Error("observe-only forwarded but recorded nothing — the decision must be audited")
	}
}

// A worker error fails OPEN: the flow is forwarded and the failure is audited (D17).
func TestProxyFailsOpenOnWorkerError(t *testing.T) {
	up, hit := upstream(t)
	led := &recLedger{}
	// erroringWorker makes classify fail; the policy is never reached.
	gw := gateway.New(erroringWorker{}, deciding(corev1.Action_ACTION_BLOCK), led, nil, time.Second)
	proxyURL := serveProxy(t, gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, true, nil))

	resp, err := proxyClient(t, proxyURL).Post(up.URL, "text/plain", strings.NewReader("anything"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a classifier failure must fail OPEN, not block egress", resp.StatusCode)
	}
	if !hit.Load() {
		t.Error("upstream not reached — fail-open must forward the flow")
	}
	if len(led.entries) == 0 {
		t.Error("the pipeline failure was not audited (D17)")
	}
}
