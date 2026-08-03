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

// SEC-C, end to end: default-deny is a property of the GATE, not of the operator's Rego text.
//
// `evalCandidate` answered ALLOW when no rule matched and the access proxy grants on ALLOW, so the only
// thing denying an unmatched request was the last line of the operator's policy:
//
//	decision := {"action":"BLOCK", ...} if { not authorized }
//
// Delete it and the proxy became default-ALLOW in front of internal services, with a diff showing one
// removed line that a reviewer had to KNOW was the whole security model.
//
// The unit tests pin the engine's behaviour. This runs the real binary, because the claim being made is
// about a deployment: a gateway handed an incomplete policy must still refuse, and a gateway handed a
// permissive one must not start at all.

// incompletePolicy authorizes the finance role and says NOTHING about anyone else — the deny line
// deleted. It is valid Rego and it compiles.
const incompletePolicy = `package openshield
import rego.v1
authorized if { input.context.role == "finance" }
decision := {"action":"ALLOW","reason":"authorized","confidence":0.9} if { authorized }`

// admitsUnknownPolicy reads like a denylist and admits every caller whose role could not be resolved.
// It MATCHES, so no default-deny can catch it — only the load-time probe can.
const admitsUnknownPolicy = `package openshield
import rego.v1
authorized if { input.context.role != "banned" }
decision := {"action":"ALLOW","reason":"not banned","confidence":0.9} if { authorized }
decision := {"action":"BLOCK","reason":"banned","confidence":0.9} if { not authorized }`

// startAccessGateway brings up a gateway in access mode with the given policy, returning the process and
// the listen address. It does NOT wait for readiness — a caller asserting that startup FAILS must be
// able to observe that.
func startAccessGateway(t *testing.T, stack *Stack, p *pki, origin *upstream, module string) (*Process, string) {
	t.Helper()
	work := t.TempDir()
	policyPath := filepath.Join(work, "access.rego")
	if err := os.WriteFile(policyPath, []byte(module), 0o600); err != nil {
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
	return gw, addr
}

// TestAGatewayWithAnIncompleteAccessPolicyStillDenies.
//
// Mutation: load the access policy with policy.New instead of policy.NewAccess (the pre-SEC-C wiring) →
// the unmatched identity is served 200 and the internal service is reached → this FAILS.
func TestAGatewayWithAnIncompleteAccessPolicyStillDenies(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)

	gw, addr := startAccessGateway(t, stack, p, origin, incompletePolicy)
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
	dial := func(cert tls.Certificate) *http.Client {
		return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
			},
		}}
	}

	// An authenticated identity that NO RULE MENTIONS. Under the old engine this was allowed, because
	// the policy no longer contained the sentence that denied it.
	wrong := p.leafCert(t, "client", "sales-app", "--group", "sales")
	resp, err := dial(wrong).Get("https://payroll/report")
	if err != nil {
		t.Fatalf("the proxy refused the connection outright: %v\n%s", err, gw.Output())
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("an identity no rule mentions was served %d. The policy's deny line is gone, so "+
			"default-deny existed only in text that is no longer there — and the gate admitted a caller "+
			"it was never told to admit\n%s", resp.StatusCode, gw.Output())
	}
	if origin.hits.Load() != 0 {
		t.Errorf("an unmatched request REACHED the internal service (%d hits)", origin.hits.Load())
	}

	// AND THE GATE STILL WORKS. A default-deny that denies everyone is an outage, not a control, and it
	// is the failure this change could plausibly introduce.
	right := p.leafCert(t, "client", "finance-app", "--group", "finance")
	ok, err := dial(right).Get("https://payroll/report")
	if err != nil {
		t.Fatalf("the authorized identity was refused: %v\n%s", err, gw.Output())
	}
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("the AUTHORIZED identity got %d — the no-match default must apply to requests no rule "+
			"matched, not to every request\n%s", ok.StatusCode, gw.Output())
	}
	if origin.hits.Load() != 1 {
		t.Errorf("the authorized request did not reach the service (%d hits)", origin.hits.Load())
	}
}

// TestAGatewayRefusesToStartOnAnAccessPolicyThatAdmitsAnUnknownPrincipal.
//
// The no-match default cannot catch this one: the policy MATCHES, it simply matches wrongly. A
// `role != "banned"` predicate reads like a denylist and admits every caller whose role could not be
// resolved at all.
//
// The assertion is that the binary EXITS. "Does not start" is the required failure mode of a Zero-Trust
// gate — the alternative is a process that comes up healthy, logs nothing unusual, and fronts an
// internal service for anyone who can complete a handshake.
//
// Mutation: drop the denyUnknownPrincipal probe from NewAccess → the gateway starts and serves → this
// FAILS.
func TestAGatewayRefusesToStartOnAnAccessPolicyThatAdmitsAnUnknownPrincipal(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)

	gw, addr := startAccessGateway(t, stack, p, origin, admitsUnknownPolicy)
	gw.WaitForOutput("admits an unknown principal", 90*time.Second)

	// IT NEVER BEGAN SERVING. Asserted through the readiness banner rather than through the process
	// state: the harness does not reap its children until teardown, so an exited gateway is a zombie and
	// every "is it alive" check answers yes. The banner is printed at the point the listener is handed
	// the connection, so its absence is the fact that matters, and it cannot be produced by a process
	// that refused its policy.
	if contains(gw.Output(), "ZERO-TRUST ACCESS MODE") {
		t.Errorf("the gateway began SERVING despite refusing its access policy — the failure mode of a "+
			"Zero-Trust gate must be \"does not start\", never \"starts and admits everyone\"\n%s",
			gw.Output())
	}
	// And nothing is listening. Checked separately, because "it logged a refusal" and "the port is
	// closed" are what an operator and an attacker respectively observe, and only the second decides
	// whether the internal service is reachable. Given a moment first, so this is not merely a race
	// against a listener that has not opened yet.
	time.Sleep(2 * time.Second)
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		_ = c.Close()
		t.Errorf("the access port %s is accepting connections after the policy was refused", addr)
	}
}
