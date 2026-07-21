package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// oneCA issues a server cert (SAN 127.0.0.1/localhost) and named client certs,
// all from a SINGLE CA, so a real mutual-TLS handshake succeeds.
type oneCA struct {
	caCert *x509.Certificate
	caKey  ed25519.PrivateKey
	pool   *x509.CertPool
}

func newOneCA(t *testing.T) *oneCA {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &oneCA{caCert: cert, caKey: priv, pool: pool}
}

func (c *oneCA) leaf(t *testing.T, cn string, ips []net.IP) tls.Certificate {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: ips,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, pub, c.caKey)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: mustParse(der)}
}

func mustParse(der []byte) *x509.Certificate { c, _ := x509.ParseCertificate(der); return c }

// seedTelemetry inserts one fleet_telemetry row so a view has something to return.
func seedTelemetry(t *testing.T, agentID, eventID string) {
	t.Helper()
	p := mustPoolCP(t)
	defer p.Close()
	if _, err := p.Exec(context.Background(),
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified) VALUES ($1,'event',$2,$3,true)`,
		agentID, eventID, []byte("x")); err != nil {
		t.Fatalf("seed telemetry: %v", err)
	}
}

// 3.1 — a view over mutual TLS records the viewer as operator:<CN> from the
// CERTIFICATE, never from the request. 3.3 rides along: the recorded label is
// distinguishable from the legacy unauthenticated library path.
func TestAuthenticatedViewRecordsCertIdentity(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{ca.leaf(t, "server", []net.IP{net.ParseIP("127.0.0.1")})},
		ClientCAs:    ca.pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeHTTPTLS(ctx, addr, serverCfg) }()
	time.Sleep(150 * time.Millisecond)

	// Seed an investigation to view (direct insert — this test exercises the view
	// path, not ingest).
	seedTelemetry(t, "agent-x", "inv-1")

	// Client with CN "alice".
	clientCfg := &tls.Config{
		Certificates: []tls.Certificate{ca.leaf(t, "alice", nil)},
		RootCAs:      ca.pool, MinVersion: tls.VersionTLS13,
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: clientCfg}, Timeout: 3 * time.Second}
	resp, err := hc.Get("https://" + addr + "/view?event=inv-1")
	if err != nil {
		t.Fatalf("authenticated view failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("view status = %d, want 200", resp.StatusCode)
	}

	// The recorded viewer is the CERT identity, not a caller string.
	views, err := srv.Views(ctx, "inv-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Viewer != "operator:alice" {
		t.Fatalf("recorded views = %+v, want one viewer 'operator:alice'", views)
	}

	// 3.3 — the legacy library path is distinguishable (unauthenticated:<user>).
	if _, err := srv.View(ctx, "unauthenticated:bob", "inv-1"); err != nil {
		t.Fatal(err)
	}
	views, _ = srv.Views(ctx, "inv-1")
	var auth, unauth int
	for _, v := range views {
		switch {
		case v.Viewer == "operator:alice":
			auth++
		case v.Viewer == "unauthenticated:bob":
			unauth++
		}
	}
	if auth != 1 || unauth != 1 {
		t.Fatalf("labels not distinguishable: %+v", views)
	}
}

// The authenticated view route exists ONLY under mutual TLS: in plaintext there
// is no verified identity to record, so exposing it would recreate the
// self-asserted gap. A plaintext server serves /enroll but NOT /view.
func TestViewRouteAbsentWithoutTLS(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeHTTP(ctx, addr) }() // plaintext
	time.Sleep(150 * time.Millisecond)

	resp, err := http.Get("http://" + addr + "/view?event=x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("plaintext /view = %d, want 404 — the authenticated route must not exist without TLS", resp.StatusCode)
	}
}

// 3.2 — a request with no verified client certificate is refused and records NO
// view: the handshake refusal under RequireAndVerifyClientCert, plus the
// defensive nil-r.TLS path returning 401 with no row.
func TestViewWithoutCertRefused(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ca := newOneCA(t)
	seedTelemetry(t, "agent-y", "inv-2")

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{ca.leaf(t, "server", []net.IP{net.ParseIP("127.0.0.1")})},
		ClientCAs:    ca.pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeHTTPTLS(ctx, addr, serverCfg) }()
	time.Sleep(150 * time.Millisecond)

	// No client cert (server-auth only): handshake refuses the request.
	noCert := &http.Client{Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.pool, MinVersion: tls.VersionTLS13}}}
	if _, err := noCert.Get("https://" + addr + "/view?event=inv-2"); err == nil {
		t.Fatal("a request with no client certificate was served")
	}

	// Defensive: the handler itself refuses a request whose r.TLS carries no peer
	// certificate (401, no row), independent of the listener config.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/view?event=inv-2", nil) // r.TLS == nil
	srv.ViewHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nil-TLS view = %d, want 401", rec.Code)
	}

	// No view was recorded by either attempt.
	views, _ := srv.Views(ctx, "inv-2")
	if len(views) != 0 {
		t.Fatalf("a refused view was recorded: %+v", views)
	}
}
