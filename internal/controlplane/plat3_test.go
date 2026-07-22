package controlplane_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/provision"
)

// PLAT-3/ADR-4: the tiered RBAC gate orders analyst < responder < admin, a higher tier satisfies a
// lower requirement, the legacy operator ranks as admin, and agent/unknown/absent is authorized for
// nothing. Tested directly against requireTier with certs of each role.
func TestRequireTierHierarchy(t *testing.T) {
	ca := newOneCA(t)
	code := func(minRole, certRole string) int {
		gate := controlplane.RequireTierForTest(minRole)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if certRole != "none" {
			leaf := ca.leaf(t, "x", certRole, nil)
			parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}
		}
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		return rr.Code
	}
	ok, forbidden, unauth := http.StatusOK, http.StatusForbidden, http.StatusUnauthorized

	// analyst gate: analyst/responder/admin/operator pass; agent 403; no cert 401.
	for _, r := range []string{"analyst", "responder", "admin", "operator"} {
		if c := code("analyst", r); c != ok {
			t.Errorf("analyst gate, %s cert = %d, want 200", r, c)
		}
	}
	if c := code("analyst", "agent"); c != forbidden {
		t.Errorf("analyst gate, agent = %d, want 403", c)
	}
	if c := code("analyst", "none"); c != unauth {
		t.Errorf("analyst gate, no cert = %d, want 401", c)
	}
	// responder gate: analyst denied; responder/admin/operator pass.
	if c := code("responder", "analyst"); c != forbidden {
		t.Errorf("responder gate, analyst = %d, want 403 (analyst ranks below responder)", c)
	}
	for _, r := range []string{"responder", "admin", "operator"} {
		if c := code("responder", r); c != ok {
			t.Errorf("responder gate, %s = %d, want 200", r, c)
		}
	}
	// admin gate: analyst/responder denied; admin/operator pass.
	for _, r := range []string{"analyst", "responder"} {
		if c := code("admin", r); c != forbidden {
			t.Errorf("admin gate, %s = %d, want 403", r, c)
		}
	}
	for _, r := range []string{"admin", "operator"} {
		if c := code("admin", r); c != ok {
			t.Errorf("admin gate, %s = %d, want 200 (legacy operator ranks as admin)", r, c)
		}
	}
}

// IssueCert accepts the new operator-tier roles and still rejects an unknown one.
func TestIssueCertAcceptsTierRoles(t *testing.T) {
	caCert, caKey, err := provision.InitCA()
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{provision.RoleAnalyst, provision.RoleResponder, provision.RoleAdmin, provision.RoleAgent, provision.RoleOperator} {
		if _, _, err := provision.IssueCert(caCert, caKey, "x", role, nil); err != nil {
			t.Errorf("IssueCert(role=%q) errored: %v", role, err)
		}
	}
	if _, _, err := provision.IssueCert(caCert, caKey, "x", "wizard", nil); err == nil {
		t.Error("IssueCert accepted an unknown role")
	}
}

// PLAT-3 end to end over real mTLS: provisioned tier certs drive the REAL per-route gates on the
// served control-plane mux — analyst reads but cannot ack or view, responder can ack, admin (and
// legacy operator) can view, and an agent is refused every operator route.
func TestRBACTiersOverServedMux(t *testing.T) {
	caCert, caKey, err := provision.InitCA()
	if err != nil {
		t.Fatal(err)
	}
	srvCertPEM, srvKeyPEM, _ := provision.IssueCert(caCert, caKey, "server", provision.RoleAgent, []string{"127.0.0.1", "localhost"})
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	serverCfg := &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}

	srv := controlplane.New(requireDB(t))
	seedTelemetry(t, "agent-t", "inv-t1")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeHTTPTLS(ctx, addr, serverCfg) }()
	time.Sleep(150 * time.Millisecond)

	clientFor := func(role string) *http.Client {
		cp, kp, err := provision.IssueCert(caCert, caKey, role+"-user", role, nil)
		if err != nil {
			t.Fatalf("issue %s cert: %v", role, err)
		}
		return clientFromPEM(t, caCert, cp, kp)
	}
	get := func(c *http.Client, path string) int {
		resp, err := c.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	post := func(c *http.Client, path string) int {
		resp, err := c.Post("https://"+addr+path, "application/json", strings.NewReader(`{"id":1}`))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	forbidden := http.StatusForbidden

	analyst, responder, admin, operator, agent := clientFor("analyst"), clientFor("responder"), clientFor("admin"), clientFor("operator"), clientFor("agent")

	// analyst: reads the queue (200), but cannot ack (403) or view (403).
	if c := get(analyst, "/alerts"); c != http.StatusOK {
		t.Errorf("analyst GET /alerts = %d, want 200", c)
	}
	if c := post(analyst, "/alerts/ack"); c != forbidden {
		t.Errorf("analyst POST /alerts/ack = %d, want 403 (ack needs responder)", c)
	}
	if c := get(analyst, "/view?event=inv-t1"); c != forbidden {
		t.Errorf("analyst GET /view = %d, want 403 (view needs admin)", c)
	}
	// responder: the ack gate admits it (not 403 — the handler's own validation may 4xx, but it is authorized).
	if c := post(responder, "/alerts/ack"); c == forbidden {
		t.Error("responder POST /alerts/ack = 403, want authorized (responder tier)")
	}
	if c := get(responder, "/view?event=inv-t1"); c != forbidden {
		t.Errorf("responder GET /view = %d, want 403 (view needs admin)", c)
	}
	// admin + legacy operator: view is served (not 403), reads served.
	for name, c := range map[string]*http.Client{"admin": admin, "operator": operator} {
		if code := get(c, "/view?event=inv-t1"); code == forbidden {
			t.Errorf("%s GET /view = 403, want authorized (admin tier)", name)
		}
		if code := get(c, "/alerts"); code != http.StatusOK {
			t.Errorf("%s GET /alerts = %d, want 200", name, code)
		}
	}
	// agent: refused every operator route, authorized for none.
	if c := get(agent, "/alerts"); c != forbidden {
		t.Errorf("agent GET /alerts = %d, want 403", c)
	}
	if c := get(agent, "/view?event=inv-t1"); c != forbidden {
		t.Errorf("agent GET /view = %d, want 403", c)
	}
}
