package controlplane_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/provision"
)

// 3.4 — drift guard: the provisioning tool's role strings MUST equal the control
// plane's D58 gate roles, or a provisioned cert would carry a role the gate does
// not recognise.
func TestProvisionRolesMatchGate(t *testing.T) {
	if provision.RoleAgent != controlplane.RoleAgent {
		t.Errorf("provision.RoleAgent %q != controlplane.RoleAgent %q", provision.RoleAgent, controlplane.RoleAgent)
	}
	if provision.RoleOperator != controlplane.RoleOperator {
		t.Errorf("provision.RoleOperator %q != controlplane.RoleOperator %q", provision.RoleOperator, controlplane.RoleOperator)
	}
}

// clientFromPEM builds an HTTP client presenting a provisioned leaf cert, trusting
// the provisioned CA.
func clientFromPEM(t *testing.T, caPEM, certPEM, keyPEM []byte) *http.Client {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA PEM not usable")
	}
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13},
	}}
}

// 3.2 — loop-closing: certs issued by the PROVISIONING TOOL drive the REAL D58
// role gate. A provisioned operator cert is authorized for /view; a provisioned
// agent cert is 403. This proves the tool's output actually works with the server.
func TestProvisionedCertsDriveRoleGate(t *testing.T) {
	caCert, caKey, err := provision.InitCA()
	if err != nil {
		t.Fatal(err)
	}
	// Server cert (SAN 127.0.0.1) + an operator and an agent client cert — all
	// from the provisioning tool.
	srvCertPEM, srvKeyPEM, _ := provision.IssueCert(caCert, caKey, "server", provision.RoleAgent, []string{"127.0.0.1", "localhost"})
	opCertPEM, opKeyPEM, _ := provision.IssueCert(caCert, caKey, "alice", provision.RoleOperator, nil)
	agCertPEM, agKeyPEM, _ := provision.IssueCert(caCert, caKey, "spy", provision.RoleAgent, nil)

	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
	}

	srv := controlplane.New(requireDB(t))
	seedTelemetry(t, "agent-p", "inv-p1")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeHTTPTLS(ctx, addr, serverCfg) }()
	time.Sleep(150 * time.Millisecond)

	// Provisioned operator cert → /view 200.
	op := clientFromPEM(t, caCert, opCertPEM, opKeyPEM)
	resp, err := op.Get("https://" + addr + "/view?event=inv-p1")
	if err != nil {
		t.Fatalf("provisioned operator /view failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("provisioned operator /view = %d, want 200", resp.StatusCode)
	}

	// Provisioned agent cert → /view 403.
	ag := clientFromPEM(t, caCert, agCertPEM, agKeyPEM)
	resp2, err := ag.Get("https://" + addr + "/view?event=inv-p1")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("provisioned agent /view = %d, want 403", resp2.StatusCode)
	}
}
