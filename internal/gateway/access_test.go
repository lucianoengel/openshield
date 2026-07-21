package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/provision"
)

// accessCA issues the server cert, client certs, and the trust pool for an access
// test.
type accessCA struct {
	caCert, caKey []byte
	pool          *x509.CertPool
}

func newAccessCA(t *testing.T) *accessCA {
	t.Helper()
	c, k, err := provision.InitCA()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	b, _ := pem.Decode(c)
	cert, _ := x509.ParseCertificate(b.Bytes)
	pool.AddCert(cert)
	return &accessCA{c, k, pool}
}

func (ca *accessCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := provision.IssueCert(ca.caCert, ca.caKey, "127.0.0.1", provision.RoleAgent, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func (ca *accessCA) clientCert(t *testing.T, identity, group string) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := provision.IssueClientCert(ca.caCert, ca.caKey, identity, group)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// A default-DENY access policy: authorized roles ALLOW, everything else BLOCK. Access
// policies are default-deny (a ZT principle) — the opposite of the observe-first
// egress default (D1) — so an unmatched request denies, not allows.
const accessPolicyRego = `package openshield
import rego.v1
authorized if { input.context.role == "finance" }
decision := {"action":"ALLOW","reason":"authorized","confidence":0.9} if { authorized }
decision := {"action":"BLOCK","reason":"not authorized","confidence":0.9} if { not authorized }`

func accessUpstream(t *testing.T) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var hit atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("internal-service"))
	}))
	t.Cleanup(s.Close)
	return s, &hit
}

// serveAccessTLS serves the access proxy over TLS REQUIRING a verified client cert.
func serveAccessTLS(t *testing.T, h http.Handler, ca *accessCA) string {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{ca.serverCert(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func accessClient(clientCert tls.Certificate, pool *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool},
	}}
}

func buildAccessGateway(t *testing.T, worker interface {
	Classify(context.Context, *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error)
}, up *httptest.Server) (*gateway.AccessProxy, *accessCA) {
	t.Helper()
	pol, err := policy.New(context.Background(), "access", "1", accessPolicyRego)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(worker, pol, &recLedger{}, nil, time.Second)
	upURL, _ := url.Parse(up.URL)
	cat := gateway.NewCatalog()
	// The D87 clients connect to the gateway at 127.0.0.1, so the request Host is
	// "127.0.0.1" — register the single service under that host.
	cat.Add("127.0.0.1", upURL)
	return gateway.NewAccessProxy(gw, cat, 0, nil), newAccessCA(t)
}

// hostReq builds a GET to the gateway addr but with an overridden Host header, so a
// client can request a named service (the catalog routes on Host, D88) while TLS still
// validates against the gateway's 127.0.0.1 cert.
func hostReq(t *testing.T, addr, host string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = host
	return r
}

// Microsegmentation (D88): the SAME identity reaches one service and is denied another.
// A finance client is authorized to payroll but not wiki.
func TestAccessMicrosegmentation(t *testing.T) {
	payroll, payrollHit := accessUpstream(t)
	wiki, wikiHit := accessUpstream(t)

	// A per-service policy: finance may reach payroll, and nothing else.
	pol, err := policy.New(context.Background(), "microseg", "1", `package openshield
import rego.v1
allowed if { input.context.role == "finance"; input.event.host == "payroll" }
decision := {"action":"ALLOW","reason":"authorized","confidence":0.9} if { allowed }
decision := {"action":"BLOCK","reason":"not authorized for this service","confidence":0.9} if { not allowed }`)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	pu, _ := url.Parse(payroll.URL)
	wu, _ := url.Parse(wiki.URL)
	cat.Add("payroll", pu)
	cat.Add("wiki", wu)
	ca := newAccessCA(t)
	addr := serveAccessTLS(t, gateway.NewAccessProxy(gw, cat, 0, nil), ca)
	client := accessClient(ca.clientCert(t, "alice@corp", "finance"), ca.pool)

	// finance → payroll: allowed.
	resp, err := client.Do(hostReq(t, addr, "payroll"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !payrollHit.Load() {
		t.Errorf("finance→payroll = %d (hit %v), want 200 + reached", resp.StatusCode, payrollHit.Load())
	}

	// finance → wiki: DENIED, wiki never reached — same identity, different service.
	resp2, err := client.Do(hostReq(t, addr, "wiki"))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("finance→wiki = %d, want 403 (microsegmentation)", resp2.StatusCode)
	}
	if wikiHit.Load() {
		t.Error("finance reached wiki — microsegmentation failed (same identity must be denied a different service)")
	}
}

// An unknown service host is refused 404 and no upstream is reached (the catalog is an
// allow-list, not an open relay, D88).
func TestAccessUnknownServiceRefused(t *testing.T) {
	up, hit := accessUpstream(t)
	ap, ca := buildAccessGateway(t, &fakeWorker{}, up) // catalog only has "127.0.0.1"
	addr := serveAccessTLS(t, ap, ca)
	client := accessClient(ca.clientCert(t, "alice@corp", "finance"), ca.pool)

	resp, err := client.Do(hostReq(t, addr, "does-not-exist"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown service = %d, want 404", resp.StatusCode)
	}
	if hit.Load() {
		t.Error("an unknown service reached an upstream — the gateway must not be an open relay")
	}
}

// An authorized identity reaches the internal service; a wrong role is denied 403 and
// the service is never hit (D87). Real TLS, real client certs.
func TestAccessProxyAuthorizesByIdentity(t *testing.T) {
	up, hit := accessUpstream(t)
	ap, ca := buildAccessGateway(t, &fakeWorker{}, up)
	addr := serveAccessTLS(t, ap, ca)

	// Finance identity → authorized → reaches the internal service.
	resp, err := accessClient(ca.clientCert(t, "alice@corp", "finance"), ca.pool).Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("authorized access failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "internal-service" {
		t.Fatalf("authorized request did not reach the service: status=%d body=%q", resp.StatusCode, body)
	}
	if !hit.Load() {
		t.Error("the internal service was not reached by an authorized identity")
	}

	// Sales identity → not authorized → 403, service never hit.
	hit.Store(false)
	resp2, err := accessClient(ca.clientCert(t, "bob@corp", "sales"), ca.pool).Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("unauthorized role = %d, want 403", resp2.StatusCode)
	}
	if hit.Load() {
		t.Error("an unauthorized identity reached the internal service")
	}
}

// A pipeline error FAILS CLOSED (403) — the opposite of the egress proxy's fail-open
// (D87). Access is denied on an error, never granted.
func TestAccessProxyFailsClosedOnError(t *testing.T) {
	up, hit := accessUpstream(t)
	ap, ca := buildAccessGateway(t, erroringWorker{}, up)
	addr := serveAccessTLS(t, ap, ca)

	resp, err := accessClient(ca.clientCert(t, "alice@corp", "finance"), ca.pool).Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("pipeline error = %d, want 403 — ACCESS must fail CLOSED (D87)", resp.StatusCode)
	}
	if hit.Load() {
		t.Error("a request reached the service despite a pipeline error — access must fail closed")
	}
}

// The Process for an access request stamps the VERIFIED identity pseudonym as the
// Event subject, replacing sha256(src-IP) (D84/D87). A capturing policy inspects it.
func TestAccessRequestSubjectIsVerifiedIdentity(t *testing.T) {
	var gotSubject string
	capture := stageFn{"policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		gotSubject = s.Event.GetSubject().GetPseudonymousId()
		return core.Decided(&corev1.Decision{DecisionId: "d", EventId: s.Event.GetEventId(), Action: corev1.Action_ACTION_ALLOW}), nil
	}}
	gw := gateway.New(&fakeWorker{}, capture, &recLedger{}, nil, time.Second)

	idCtx := &core.Context{Identity: "sub_verified_alice", Role: "finance"}
	r := req("flow-1", "")
	r.SrcIP = "10.0.0.9"
	r.Identity = idCtx
	if _, err := gw.Process(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if gotSubject != "sub_verified_alice" {
		t.Errorf("event subject = %q, want the verified identity pseudonym (not the src IP) — D87", gotSubject)
	}
}
