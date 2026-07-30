package ztna_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/ztna"
)

// selfSigned mints a throwaway certificate to stand in for the enrolled device identity. The broker in
// these tests does not verify it — what is being asserted is what the CLIENT does with it, not the
// server-side authorization that ZT-1/ZT-3 cover elsewhere.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device-under-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// brokerClient starts a TLS broker running h and returns a Client pointed at it.
func brokerClient(t *testing.T, token string, h http.HandlerFunc) (*ztna.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ztna.New(u, selfSigned(t), &tls.Config{RootCAs: pool}, token)
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

// "A broker that starts without the identity it exists to present would forward traffic unauthenticated
// while looking like protection, which is worse than not running at all."
func TestNewRefusesWithoutADeviceIdentity(t *testing.T) {
	u, _ := url.Parse("https://broker.example")
	c, err := ztna.New(u, tls.Certificate{}, &tls.Config{}, "tok")
	if !errors.Is(err, ztna.ErrNoDeviceIdentity) {
		t.Fatalf("got %v, want ErrNoDeviceIdentity", err)
	}
	if c != nil {
		t.Fatal("a client was returned alongside the refusal")
	}

	if _, err := ztna.New(nil, selfSigned(t), &tls.Config{}, "tok"); err == nil {
		t.Fatal("a client was built with no broker URL")
	}
}

// THE SHARPEST PROPERTY HERE. The broker presents THIS DEVICE's certificate on every request it forwards,
// so a broker bound to a routable interface is a relay any host on the LAN can drive with this device's
// identity — an authorization bypass that requires no exploit, only a route.
func TestTheBrokerBindsLoopbackOnly(t *testing.T) {
	c, _ := brokerClient(t, "tok", func(http.ResponseWriter, *http.Request) {})

	// EVERY ADDRESS USES PORT 0, and the call runs in a goroutine. Both are consequences of what happens
	// when the guard is not there: ListenAndServe BINDS and then BLOCKS in http.Serve forever. A
	// synchronous call would hang rather than fail, which is how the first version of this test wedged a
	// mutation run for ten minutes instead of reporting a killed mutant. A guard that is gone must show up
	// as a failing test, never as a hang — and port 0 keeps a regression from seizing a real service port.
	for _, addr := range []string{
		"0.0.0.0:0",
		":0",
		"192.168.1.10:0",
		"10.0.0.5:0",
		"[::]:0",
		"example.internal:0",
	} {
		t.Run("refuse "+addr, func(t *testing.T) {
			errc := make(chan error, 1)
			go func() { errc <- c.ListenAndServe(addr) }()
			select {
			case err := <-errc:
				if err == nil {
					t.Fatalf("the broker bound %q — any host that can route here could use this device's "+
						"identity to reach internal services", addr)
				}
				if !strings.Contains(err.Error(), "loopback") {
					t.Fatalf("bind was refused for the wrong reason (%v); a port-in-use or "+
						"address-not-available error would pass a weaker test while the loopback guard "+
						"was gone", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("ListenAndServe(%q) did not return: it BOUND a non-loopback address and is now "+
					"serving on it, which is exactly the relay this guard exists to prevent", addr)
			}
		})
	}

	// And the loopback forms must be ACCEPTED, or the guard is just "never start".
	for _, addr := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0"} {
		t.Run("accept "+addr, func(t *testing.T) {
			errc := make(chan error, 1)
			go func() { errc <- c.ListenAndServe(addr) }()
			select {
			case err := <-errc:
				if err != nil && strings.Contains(err.Error(), "loopback") {
					t.Fatalf("a loopback address was refused: %v", err)
				}
			case <-time.After(300 * time.Millisecond):
				// Still serving, which is the pass: it got past the guard and bound.
			}
		})
	}
}

// "It NEVER falls back: a refusal from the broker is returned to the application as an error, and no direct
// connection to the internal service is attempted. A client that 'helpfully' retried would turn a
// Zero-Trust denial into an ordinary network request — the worst available outcome."
func TestABrokerRefusalIsSurfacedAndNeverRetried(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls int
			c, _ := brokerClient(t, "tok", func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "access denied by policy: wiki not in your catalog")
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://wiki.internal/page", nil)
			c.ServeHTTP(rec, req)

			if rec.Code != status {
				t.Fatalf("got %d, want the broker's own %d", rec.Code, status)
			}
			// The operator debugging "why can't I reach the wiki" needs the broker's reason, not an
			// opaque failure.
			if !strings.Contains(rec.Body.String(), "not in your catalog") {
				t.Fatalf("the broker's reason was dropped: %q", rec.Body.String())
			}
			if calls != 1 {
				t.Fatalf("the broker was called %d times — a denial must not be retried", calls)
			}
		})
	}
}

func TestAnUnreachableBrokerIsAnErrorNotADirectConnection(t *testing.T) {
	// Point at a closed port: nothing is listening, so any success would mean the client went somewhere
	// other than the broker.
	u, _ := url.Parse("https://127.0.0.1:1")
	c, err := ztna.New(u, selfSigned(t), &tls.Config{}, "tok")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://wiki.internal/page", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502 — an unreachable broker must fail, never fall through to the service",
			rec.Code)
	}
}

func TestTheDeviceTokenAndHostReachTheBroker(t *testing.T) {
	var gotAuth, gotHost, gotPath, gotQuery string
	c, _ := brokerClient(t, "user-token", func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotHost, gotPath, gotQuery = r.Header.Get("Authorization"), r.Host, r.URL.Path, r.URL.RawQuery
		_, _ = io.WriteString(w, "ok")
	})

	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://wiki.internal/a/b?x=1", nil))

	if gotAuth != "Bearer user-token" {
		t.Fatalf("Authorization = %q, want the bearer token", gotAuth)
	}
	// The internal service is selected by the requested HOST, which the broker resolves through its
	// allow-list catalog (D88). Lose it and every request targets the broker itself.
	if gotHost != "wiki.internal" {
		t.Fatalf("Host = %q, want wiki.internal — the broker cannot tell which service was asked for", gotHost)
	}
	if gotPath != "/a/b" || gotQuery != "x=1" {
		t.Fatalf("path/query = %q %q, want /a/b x=1", gotPath, gotQuery)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("the broker's response did not reach the application: %d %q", rec.Code, rec.Body.String())
	}
}

// Hop-by-hop headers are per-connection and must not be relayed onto a different connection.
func TestHopByHopHeadersAreNotForwarded(t *testing.T) {
	var seen http.Header
	c, _ := brokerClient(t, "", func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = io.WriteString(w, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "http://wiki.internal/", nil)
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("TE", "trailers")
	req.Header.Set("X-Real-Header", "kept")
	c.ServeHTTP(httptest.NewRecorder(), req)

	for _, h := range []string{"Proxy-Connection", "Keep-Alive", "Upgrade", "TE"} {
		if v := seen.Get(h); v != "" {
			t.Errorf("hop-by-hop header %s was forwarded to the broker as %q", h, v)
		}
	}
	if seen.Get("X-Real-Header") != "kept" {
		t.Error("an ordinary header was dropped — the filter is removing more than the hop-by-hop set")
	}
}

// "A brokered request must not be silently redirected somewhere else: the broker's answer is the answer,
// and following a redirect could take the request off the authorized path."
func TestARedirectFromTheBrokerIsNotFollowed(t *testing.T) {
	var hits []string
	c, _ := brokerClient(t, "tok", func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path != "/elsewhere" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "FOLLOWED")
	})

	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://wiki.internal/start", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("got %d, want the 302 passed straight back to the application", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "FOLLOWED") || len(hits) != 1 {
		t.Fatalf("the client followed the redirect (hits=%v) — a brokered request could be taken off the "+
			"authorized path by the response to it", hits)
	}
}
