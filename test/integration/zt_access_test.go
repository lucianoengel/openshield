//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE ZERO-TRUST ACCESS PROXY (D305).
//
// The gateway has TWO modes and the suite only ever ran one. Access mode is a different product surface:
// a client-certificate-authenticated reverse proxy in front of internal services, with a DEFAULT-DENY
// identity-aware policy (D87). It is the mode where "who are you" is the whole question, and it had
// never been started by anything but a package test.
//
// The property that distinguishes it from the egress proxy is the default: the observe-first policy is
// default-ALLOW, and this one MUST NOT be. A misconfiguration that fell back to the egress default would
// admit everyone to every internal service — which is why the binary aborts rather than defaulting when
// the access policy is missing, and why the first scenario here asserts a request with NO certificate is
// refused before anything else.

// accessPolicy is default-deny and role-aware: only a certificate whose CN says finance gets through.
// The identity's SUBJECT is a pseudonym of the certificate's CN (D23) — the policy never sees the raw
// name — so authorization is on the GROUP, which is what the certificate's Organization carries and what
// a real access policy matches on.
const accessPolicy = `package openshield
import rego.v1
authorized if { input.context.role == "finance" }
decision := {"action":"ALLOW","reason":"authorized","confidence":0.9} if { authorized }
decision := {"action":"BLOCK","reason":"not authorized","confidence":0.9} if { not authorized }`

func TestTheAccessProxyIsDefaultDenyAndIdentityAware(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)
	work := t.TempDir()

	policyPath := filepath.Join(work, "access.rego")
	if err := os.WriteFile(policyPath, []byte(accessPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	m := p.serverMaterial(t)
	addr := "127.0.0.1:" + freePort(t)

	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_ACCESS_MODE=1",
		"OPENSHIELD_ACCESS_LISTEN=" + addr,
		"OPENSHIELD_ACCESS_CLIENT_CA=" + p.caPEM,
		"OPENSHIELD_ACCESS_SERVER_CERT=" + m.Cert,
		"OPENSHIELD_ACCESS_SERVER_KEY=" + m.Key,
		"OPENSHIELD_ACCESS_POLICY=" + policyPath,
		"OPENSHIELD_ACCESS_CATALOG=payroll=http://" + origin.addr,
	})
	gw.WaitForOutput("ZERO-TRUST ACCESS MODE", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)

	caPEM, err := os.ReadFile(p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA did not parse")
	}
	// The catalog resolves by HOST, so every request presents the service name as its authority while
	// dialling the proxy's address.
	dial := func(cert *tls.Certificate) *http.Client {
		cfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
			TLSClientConfig: cfg,
			// The catalog resolves by HOST, so the request names the service and the dial goes to the
			// proxy — which is exactly how a client reaches it behind DNS in a deployment.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
			},
		}}
	}

	// 1. NO CLIENT CERTIFICATE: refused at the TLS layer. Asserting this first because it is the
	// property everything else depends on — an access proxy that will talk to an unauthenticated client
	// has already lost, whatever its policy says.
	if _, err := dial(nil).Get("https://payroll/report"); err == nil {
		t.Fatal("a request with NO client certificate was served — the access proxy authenticates at the " +
			"TLS layer, and one that does not is a reverse proxy with extra steps")
	}
	if origin.hits.Load() != 0 {
		t.Fatalf("an unauthenticated request REACHED the internal service (%d hits)", origin.hits.Load())
	}

	// 2. AN AUTHENTICATED BUT UNAUTHORIZED identity: default-DENY. This is the half a fallback to the
	// egress policy would break, and it would break it open.
	wrong := p.leafCert(t, "client", "sales-app", "--group", "sales")
	resp, err := dial(&wrong).Get("https://payroll/report")
	if err != nil {
		t.Fatalf("the proxy refused the connection outright for an authenticated client: %v\n%s", err, gw.Output())
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("an UNAUTHORIZED identity was served %d — the access policy is default-deny (D87), and "+
			"a proxy that admits any valid certificate authorizes nothing", resp.StatusCode)
	}
	if origin.hits.Load() != 0 {
		t.Errorf("an unauthorized request reached the internal service (%d hits) — the denial must happen "+
			"BEFORE the upstream, or the service has already served it", origin.hits.Load())
	}

	// 3. THE AUTHORIZED identity is served, and the request reaches the service.
	right := p.leafCert(t, "client", "finance-app", "--group", "finance")
	ok, err := dial(&right).Get("https://payroll/report")
	if err != nil {
		t.Fatalf("the authorized identity was refused: %v\n%s", err, gw.Output())
	}
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("the AUTHORIZED identity got %d — a default-deny proxy that denies everyone is an "+
			"outage, not a control\n%s", ok.StatusCode, gw.Output())
	}
	if origin.hits.Load() != 1 {
		t.Errorf("the authorized request did not reach the service (%d hits)", origin.hits.Load())
	}
}
