package gateway_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/ztna"
)

// ZT-4: the ENDPOINT-brokered access path, against the REAL access proxy.
//
// Everything below the client is real: a real upstream service, a real gateway.AccessProxy with a real
// default-deny Rego policy, real mutual TLS with a real CA-issued device certificate. The client is the
// only new piece, which is the point — the server half already authorized correctly, and ZT-4 is the half
// that makes the DEVICE present its identity instead of every application being reconfigured by hand.

// startBrokerClient runs the ztna client on loopback and returns an http.Client that goes through it.
func startBrokerClient(t *testing.T, brokerAddr string, cert tls.Certificate, ca *accessCA) (*http.Client, *ztna.Client) {
	t.Helper()
	brokerURL, err := url.Parse("https://" + brokerAddr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ztna.New(brokerURL, cert, &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12}, "")
	if err != nil {
		t.Fatalf("building the ZTNA client: %v", err)
	}
	c.Logf = func(format string, a ...any) { t.Logf("ztna: "+format, a...) }

	// Serve the local broker on loopback, and point an ordinary HTTP client at it exactly as an
	// application would with HTTP_PROXY.
	proxySrv := &http.Server{Handler: c}
	ln, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatal(lerr)
	}
	go func() { _ = proxySrv.Serve(ln) }()
	t.Cleanup(func() { _ = proxySrv.Close() })

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}, c
}

// TestZTNAClientBrokersAuthorizedAccess: an authorized device reaches the internal service THROUGH the
// local broker, with the device certificate as the connection's identity.
func TestZTNAClientBrokersAuthorizedAccess(t *testing.T) {
	up, upHit := accessUpstream(t)
	ap, ca := buildAccessGateway(t, &fakeWorker{}, up)
	addr := serveAccessTLS(t, ap, ca)

	// A device certificate in the authorized group.
	app, _ := startBrokerClient(t, addr, ca.clientCert(t, "device-1", "finance"), ca)

	resp, err := app.Get("http://127.0.0.1/") // an ordinary app request, brokered
	if err != nil {
		t.Fatalf("brokered request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "internal-service") {
		t.Fatalf("brokered request got %d %q, want the internal service's response", resp.StatusCode, body)
	}
	if !upHit.Load() {
		t.Fatal("the internal service was never reached through the broker")
	}
}

// TestZTNAClientSurfacesRefusalAndNeverFallsBack: an unauthorized device is refused, the broker's reason
// reaches the application, and the client does NOT reach the upstream by another route.
//
// Mutation: fall back to a direct connection on refusal → the upstream IS hit → this FAILS.
//
// HONEST NOTE on that mutation: a naive version of it (retrying `http://<Host>/`) does NOT hit the upstream
// and so does NOT fail this test — because the client structurally CANNOT find the internal service. It
// knows only the broker's address; the upstream is resolved by the broker's allow-list catalog (D88). The
// no-fallback property is therefore partly structural, and this test guards the part that is not: that a
// refusal is surfaced rather than swallowed, and that nothing else reaches the upstream.
func TestZTNAClientSurfacesRefusalAndNeverFallsBack(t *testing.T) {
	up, upHit := accessUpstream(t)
	ap, ca := buildAccessGateway(t, &fakeWorker{}, up)
	addr := serveAccessTLS(t, ap, ca)

	// A device certificate in an UNAUTHORIZED group: the default-deny policy blocks it.
	app, _ := startBrokerClient(t, addr, ca.clientCert(t, "device-2", "interns"), ca)

	resp, err := app.Get("http://127.0.0.1/")
	if err != nil {
		t.Fatalf("the refused request should return a response, not a transport error: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("an unauthorized device got 200 through the broker: %q", body)
	}
	if !strings.Contains(strings.ToLower(string(body)), "refused") {
		t.Errorf("the refusal reason was not surfaced to the application: %q", body)
	}
	if upHit.Load() {
		t.Fatal("the internal service was reached despite the refusal — the client fell back to a direct " +
			"connection, turning a Zero-Trust denial into an ordinary request")
	}
}

// TestZTNAClientRefusesWithoutADeviceIdentity: a broker with no identity to present must not start.
func TestZTNAClientRefusesWithoutADeviceIdentity(t *testing.T) {
	u, _ := url.Parse("https://127.0.0.1:1")
	if _, err := ztna.New(u, tls.Certificate{}, &tls.Config{MinVersion: tls.VersionTLS12}, ""); err == nil {
		t.Fatal("the client started without a device certificate — it would forward traffic " +
			"unauthenticated while looking like protection")
	}
}

// TestZTNAClientBindsLoopbackOnly: a broker on a routable interface is a relay anyone on the LAN could
// drive with THIS DEVICE's identity.
//
// Mutation: drop the loopback check → binding 0.0.0.0 succeeds → this FAILS.
func TestZTNAClientBindsLoopbackOnly(t *testing.T) {
	u, _ := url.Parse("https://127.0.0.1:1")
	ca := newAccessCA(t)
	c, err := ztna.New(u, ca.clientCert(t, "d", "finance"), &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS12}, "")
	if err != nil {
		t.Fatal(err)
	}
	// ListenAndServe BLOCKS when it succeeds, so the refusal must arrive promptly rather than being
	// awaited forever — a hanging test is not a failing test, and the first version of this hung.
	for _, addr := range []string{"0.0.0.0:0", "192.168.1.1:8080"} {
		errCh := make(chan error, 1)
		go func() { errCh <- c.ListenAndServe(addr) }()
		select {
		case err := <-errCh:
			if err == nil {
				t.Errorf("the broker accepted a non-loopback bind %q — anyone on the network could then "+
					"use this device's identity to reach internal services", addr)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("binding %q neither failed nor returned — the loopback restriction is not enforced "+
				"and the broker is now serving on a routable interface", addr)
		}
	}
}
