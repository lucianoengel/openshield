//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	canonid "github.com/lucianoengel/openshield/internal/pseudonym"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// RISK-DRIVEN CONTINUOUS VERIFICATION, WITH KEYS FROM THE SHIPPED TOOL (SEC-1/D89/D91).
//
// `openshield-provision risk-keygen` had NEVER been invoked by the suite. Every scenario touching the
// risk path minted its keypair in Go, so the bytes the provisioning tool actually writes had never been
// handed to either consumer — the server that signs risk, or the gateway that verifies it.
//
// That is the D339 shape: producer and consumer agree in tests that construct their own material, and
// nobody checks the artefact an operator is told to create. A format mismatch there would leave a
// deployment where risk NEVER ARRIVES — and the gateway's degraded mode for that is to apply no risk at
// all, so continuous verification silently evaluates every subject as unremarkable.
//
// THE ASSERTION IS ON AN ACCESS DECISION, not on a log line: the same request succeeds, then is refused
// once risk is published for that subject. Nothing else about the request changes.

// riskPolicy denies above a risk threshold and allows below it. What FLIPS the decision is the RISK
// SCORE alone, so it can only change if a published update was verified and reached the policy input — a
// policy keyed on the certificate would pass whether or not any risk was ever applied.
//
// The identity guard is not decoration and was added when SEC-C's load-time probe refused this policy.
// Keyed on risk alone, an unknown caller carries score 0, `risky` is false, and `not risky` ALLOWS —
// so the fixture was a gate that admitted anyone it knew nothing about. That is precisely what the probe
// exists to catch, and a test fixture is not a good enough reason to make it blind to it. Risk still
// decides everything this scenario asserts.
const riskPolicy = `package openshield
import rego.v1
known if { input.context.identity != "" }
risky if { input.context.risk_score >= 0.8 }
decision := {"action":"BLOCK","reason":"unknown principal","confidence":0.9} if { not known }
decision := {"action":"BLOCK","reason":"risk too high for this resource","confidence":0.9} if { known; risky }
decision := {"action":"ALLOW","reason":"risk acceptable","confidence":0.9} if { known; not risky }`

// publishRisk signs a RiskUpdate with the key the PROVISIONING TOOL produced and publishes it the way
// the control plane does. The test stands in for the server here deliberately: what is under test is
// whether the tool's key material is accepted by the gateway, not the server's scheduling.
func publishRisk(t *testing.T, natsURL, privPath, subject string, score float64) {
	t.Helper()
	raw, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		t.Fatalf("risk-keygen wrote a %d-byte private key; ed25519 is %d. The gateway's loader would "+
			"refuse it, so risk would never be applied in a deployment provisioned by the shipped tool",
			len(raw), ed25519.PrivateKeySize)
	}
	payload, err := proto.Marshal(&corev1.RiskUpdate{
		Subject: subject, RiskScore: score, ComputedAt: timestamppb.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := proto.Marshal(&corev1.SignedUpdate{
		Payload: payload, Signature: ed25519.Sign(ed25519.PrivateKey(raw), payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connecting to publish risk: %v", err)
	}
	defer conn.Close()
	if err := conn.Publish(natsx.SubjectRisk, signed); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
}

// TestRiskFromTheProvisioningToolReachesAnAccessDecision.
func TestRiskFromTheProvisioningToolReachesAnAccessDecision(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	origin := startUpstream(t)
	p := newPKI(t)
	m := p.serverMaterial(t)
	addr := "127.0.0.1:" + freePort(t)

	// THE KEYPAIR COMES FROM THE SHIPPED TOOL — the whole point of the scenario.
	keyDir := filepath.Join(work, "riskkeys")
	if out, err := runCapture(t, "openshield-provision", nil, "risk-keygen", "--out", keyDir); err != nil {
		t.Fatalf("risk-keygen: %v\n%s", err, out)
	}
	riskPub := filepath.Join(keyDir, "risk-pub")
	riskPriv := filepath.Join(keyDir, "risk-priv")
	for _, f := range []string{riskPub, riskPriv} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("risk-keygen did not write %s: %v", f, err)
		}
	}

	policyPath := filepath.Join(work, "risk.rego")
	if err := os.WriteFile(policyPath, []byte(riskPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_ACCESS_MODE=1",
		"OPENSHIELD_ACCESS_LISTEN=" + addr,
		"OPENSHIELD_ACCESS_CLIENT_CA=" + p.caPEM,
		"OPENSHIELD_ACCESS_SERVER_CERT=" + m.Cert,
		"OPENSHIELD_ACCESS_SERVER_KEY=" + m.Key,
		"OPENSHIELD_ACCESS_POLICY=" + policyPath,
		"OPENSHIELD_ACCESS_CATALOG=payroll=http://" + origin.addr,
		"OPENSHIELD_RISK_PUBKEY=" + riskPub,
	})

	// THE GATEWAY ACCEPTED THE TOOL'S PUBLIC KEY. If the format did not match its loader the process
	// would have exited — a startup failure is the GOOD outcome of a mismatch, and the silent one is
	// what the log line below rules out: without the key it runs on with risk verification INERT.
	gw.WaitForOutput("SIGNED risk subscription active", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)

	client := accessClient(t, p, addr)
	get := func() int {
		t.Helper()
		resp, err := client.Get("https://payroll/report")
		if err != nil {
			t.Fatalf("access request: %v\n%s", err, gw.Output())
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// 1. BEFORE ANY RISK — the request succeeds. Without this the refusal below is satisfied by a
	// gateway that refuses everything, which is an outage rather than continuous verification.
	if code := get(); code != http.StatusOK {
		t.Fatalf("an access request was refused BEFORE any risk was published (%d) — the scenario "+
			"cannot then show that risk caused anything\n%s", code, gw.Output())
	}

	// 2. RISK IS PUBLISHED for this subject, signed with the tool's private key.
	subject := accessSubject("risk-device")
	publishRisk(t, stack.NATSURL, riskPriv, subject, 0.95)

	// 3. THE SAME REQUEST IS NOW REFUSED. Nothing about it changed except the risk the gateway holds.
	deadline := time.Now().Add(60 * time.Second)
	var last int
	for time.Now().Before(deadline) {
		if last = get(); last == http.StatusForbidden {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if last != http.StatusForbidden {
		t.Errorf("after publishing risk 0.95 for %q the request still returned %d. Either the signed "+
			"update was not verified with the key risk-keygen wrote, or the risk never reached the "+
			"policy input — in a real deployment that is continuous verification evaluating every "+
			"subject as unremarkable, silently\n%s", subject, last, gw.Output())
	}
}

// accessClient dials the access proxy with a device certificate, resolving the catalog service by host
// the way a client behind DNS would.
func accessClient(t *testing.T, p *pki, proxyAddr string) *http.Client {
	t.Helper()
	cert := p.leafCert(t, "client", "risk-device", "--group", "devices")
	caPEM, err := os.ReadFile(p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the CA certificate did not parse")
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert}, RootCAs: pool,
				ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
			},
			// The catalog resolves by HOST, so the request NAMES the service and the dial goes to the
			// proxy — the same shape a client behind DNS would have. Addressing the proxy directly and
			// putting the service in the path yields a 404, because no catalogued host was named.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, proxyAddr)
			},
		},
	}
}

// accessSubject is the PSEUDONYM the gateway assigns this client (IDENT-1), which is what the risk
// store is keyed on.
//
// It calls the SAME canonicaliser the gateway does rather than recomputing the rule, so this is using a
// shared contract, not reimplementing one — a test that re-derived the mapping would agree with itself
// whatever the gateway did. What it therefore does NOT test is the identity mapping, which has its own
// tests; this scenario is about the risk path.
func accessSubject(commonName string) string { return canonid.Of(commonName) }
