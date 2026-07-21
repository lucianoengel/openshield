package controlplane_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/controlplane"
)

// serveRoleGated starts a role-gated mutual-TLS control plane and returns its
// address and CA pool.
func serveRoleGated(t *testing.T, srv *controlplane.Server, ca *oneCA) string {
	t.Helper()
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{ca.leaf(t, "server", "", []net.IP{net.ParseIP("127.0.0.1")})},
		ClientCAs:    ca.pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.ServeHTTPTLS(ctx, addr, serverCfg) }()
	time.Sleep(150 * time.Millisecond)
	return addr
}

// clientWith builds an HTTP client presenting a cert with the given role (OU).
func clientWith(t *testing.T, ca *oneCA, cn, role string) *http.Client {
	t.Helper()
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{ca.leaf(t, cn, role, nil)},
			RootCAs:      ca.pool, MinVersion: tls.VersionTLS13,
		}}}
}

// 3.1 — /view requires the operator role: an operator cert is served, an agent
// cert is 403 (authenticated but not authorized) and records no view.
func TestViewRequiresOperatorRole(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)
	seedTelemetry(t, "agent-z", "inv-r1")

	// Operator cert → 200.
	op := clientWith(t, ca, "alice", "operator")
	resp, err := op.Get("https://" + addr + "/view?event=inv-r1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator /view = %d, want 200", resp.StatusCode)
	}

	// Agent cert → 403, and it records NO view (the handler never runs).
	ag := clientWith(t, ca, "spy-agent", "agent")
	resp2, err := ag.Get("https://" + addr + "/view?event=inv-r1")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("agent /view = %d, want 403 — the D56 hole is open", resp2.StatusCode)
	}
	views, _ := srv.Views(context.Background(), "inv-r1")
	if len(views) != 1 || views[0].Viewer != "operator:alice" {
		t.Fatalf("views = %+v, want exactly the operator's — the agent's 403 must record nothing", views)
	}
}

// 3.2 — /enroll requires the agent role: an agent cert enrolls, an operator cert
// is 403 (cannot masquerade as an agent onboarding).
func TestEnrollRequiresAgentRole(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	ca := newOneCA(t)
	addr := serveRoleGated(t, srv, ca)

	body := func() *bytes.Reader {
		tok, _ := srv.IssueToken(context.Background(), time.Hour, time.Now())
		id, _ := identity.Generate("a1")
		b, _ := json.Marshal(map[string]string{
			"token": tok, "agent_id": "a1",
			"public_key": base64.StdEncoding.EncodeToString(id.PublicKey()),
		})
		return bytes.NewReader(b)
	}

	// Agent cert → 200.
	ag := clientWith(t, ca, "a1", "agent")
	resp, err := ag.Post("https://"+addr+"/enroll", "application/json", body())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agent /enroll = %d, want 200", resp.StatusCode)
	}

	// Operator cert → 403 (cannot enroll as an agent).
	op := clientWith(t, ca, "alice", "operator")
	resp2, err := op.Post("https://"+addr+"/enroll", "application/json", body())
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("operator /enroll = %d, want 403", resp2.StatusCode)
	}
}

// 3.3 — the outcomes are distinct: no verified cert → 401, a verified cert of the
// wrong (or unrecognised) role → 403. Tested directly against the role gate.
func TestRoleGateOutcomesDistinct(t *testing.T) {
	ca := newOneCA(t)
	gate := controlplane.RequireRoleForTest("operator")

	// No cert (r.TLS nil) → 401.
	rec := httptest.NewRecorder()
	gate.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/view", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no cert = %d, want 401", rec.Code)
	}

	// Verified cert, WRONG role → 403.
	withCert := func(role string) int {
		leaf := ca.leaf(t, "x", role, nil)
		parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
		req := httptest.NewRequest(http.MethodGet, "/view", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := withCert("agent"); code != http.StatusForbidden {
		t.Fatalf("wrong-role (agent) = %d, want 403", code)
	}
	if code := withCert(""); code != http.StatusForbidden {
		t.Fatalf("unrecognised-role = %d, want 403 (deny by default)", code)
	}
	if code := withCert("operator"); code != http.StatusOK {
		t.Fatalf("correct-role (operator) = %d, want 200", code)
	}
}
