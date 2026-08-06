//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE REAL ENDPOINT AGENT'S DEVICE POSTURE (CONSOLE-8d).
//
// Only cmd/openshield-fleet-agent — the fleet SIMULATOR — published posture, so the gateway's
// PostureStore was fed exclusively by simulated hosts. D85's tamper-lockout says "a device with NO
// posture published is UNTRUSTED", which means a deployment that turned posture on DENIED every real
// endpoint and admitted only the simulation. A control that refuses everything is as useless as one that
// refuses nothing, and it fails in the direction that gets it switched off.
//
// The existing coverage asserted the gateway's SUBSCRIPTION was active. That is the receiver; nothing
// proved a producer existed.

// posturePolicy is default-deny AND posture-requiring: the right role is not enough, the device must
// have published posture. That second clause is the whole of D85.
const posturePolicy = `package openshield
import rego.v1
authorized if {
	input.context.role == "finance"
	input.context.device_posture.has_posture
}
decision := {"action":"ALLOW","reason":"authorized and attested-present","confidence":0.9} if { authorized }
decision := {"action":"BLOCK","reason":"unauthorized or no device posture","confidence":0.9} if { not authorized }`

// TestTheRealEnginesPostureIsWhatUnlocksThePostureRequiringPolicy.
//
// BEFORE AND AFTER ON THE SAME GATEWAY, which is the only way to show the endpoint's posture is what
// changed the decision. Asserting only the allowed case would pass against a policy that ignores posture
// entirely — the vacuous half of every "the control works" test.
func TestTheRealEnginesPostureIsWhatUnlocksThePostureRequiringPolicy(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	work := t.TempDir()
	p := newPKI(t)
	m := p.serverMaterial(t)
	origin := startUpstream(t)

	const agentID = "engine-posture-1"

	// The operator enrols THIS endpoint's own posture key. Per-agent by design (SEC-12): one shared key
	// would let any endpoint forge another's compliance.
	roster := filepath.Join(work, "posture.roster")
	out, err := runCapture(t, "openshield-provision", nil, "posture-enroll",
		"--agent", agentID, "--roster", roster, "--out", work)
	if err != nil {
		t.Fatalf("enrolling the endpoint's posture key: %v\n%s", err, out)
	}
	postureKey := filepath.Join(work, "posture-priv")
	if _, serr := os.Stat(postureKey); serr != nil {
		t.Fatalf("posture-enroll produced no key: %v\n%s", serr, out)
	}

	policyPath := filepath.Join(work, "access.rego")
	if werr := os.WriteFile(policyPath, []byte(posturePolicy), 0o600); werr != nil {
		t.Fatal(werr)
	}
	addr := "127.0.0.1:" + freePort(t)
	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "gw-signer.state"),
		"OPENSHIELD_ACCESS_MODE=1",
		"OPENSHIELD_ACCESS_LISTEN=" + addr,
		"OPENSHIELD_ACCESS_CLIENT_CA=" + p.caPEM,
		"OPENSHIELD_ACCESS_SERVER_CERT=" + m.Cert,
		"OPENSHIELD_ACCESS_SERVER_KEY=" + m.Key,
		"OPENSHIELD_ACCESS_POLICY=" + policyPath,
		"OPENSHIELD_ACCESS_CATALOG=payroll=http://" + origin.addr,
		"OPENSHIELD_POSTURE_ROSTER=" + roster,
	})
	gw.WaitForOutput("SIGNED device-posture subscription active", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)

	// THE CLIENT IS THIS ENDPOINT. Its certificate CN is the agent id, and the proxy derives the device
	// subject as the canonical pseudonym of the CN — the same derivation the engine signs its posture
	// under, and the same one the roster loader keys by. That triple agreement is what makes posture
	// reach the decision at all (ADR-6/IDENT-1); a mismatch anywhere leaves it silently unapplied.
	cert := p.leafCert(t, "client", agentID, "--group", "finance")
	caPEM, rerr := os.ReadFile(p.caPEM)
	if rerr != nil {
		t.Fatal(rerr)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA did not parse")
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		},
	}}
	get := func() int {
		resp, gerr := client.Get("https://payroll/report")
		if gerr != nil {
			t.Fatalf("the proxy refused the connection outright: %v\n%s", gerr, gw.Output())
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	// BEFORE: the right identity, the right role, and NO POSTURE — denied. This is the state every real
	// endpoint was permanently in.
	if code := get(); code == http.StatusOK {
		t.Fatalf("a device with NO published posture was ALLOWED through a posture-requiring policy — "+
			"D85's tamper-lockout says absent posture is untrusted, and without that this test's "+
			"'after' half would prove nothing\n%s", gw.Output())
	}
	if origin.hits.Load() != 0 {
		t.Fatalf("the request REACHED the internal service with no posture (%d hits)", origin.hits.Load())
	}

	// Now the real endpoint starts and reports its own posture.
	token := issueToken(t, stack, agentID)
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		// ITS OWN DATABASE. The forward-secure ledger (T-017) refuses a signer that does not hold the
		// stored chain's keys, and the gateway already opened a chain on the shared one — two components
		// with separate signer files cannot share a ledger, which is the property working as intended.
		"OPENSHIELD_DSN=" + stack.DSNFor(t, "endpoint"),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "eng-signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_POSTURE_SIGNING_KEY=" + postureKey,
		"OPENSHIELD_POSTURE_INTERVAL=1s",
	})
	eng.WaitForOutput("SIGNED device-posture reporting ACTIVE", 90*time.Second)

	// AFTER: the same client, the same policy, the same gateway — allowed, because the endpoint now
	// says what it is.
	Eventually(t, 90*time.Second, "the endpoint's posture to unlock the posture-requiring policy",
		func() bool { return get() == http.StatusOK })

	if origin.hits.Load() == 0 {
		t.Errorf("the request was allowed and never reached the internal service (%d hits)",
			origin.hits.Load())
	}
	if contains(gw.Output(), "posture channel inert") {
		t.Errorf("the gateway loaded a roster AND reported the channel inert\n%s", gw.Output())
	}
}

// TestAnEngineWithNoPostureKeySaysWhatThatCosts.
//
// Declining posture is legitimate — it needs a per-agent key an operator has to mint. Discovering during
// an incident that the gateway has been denying this host all along is not (D31).
//
// Mutation: drop the OFF branch's log line from startPostureReporting → FAILS.
func TestAnEngineWithNoPostureKeySaysWhatThatCosts(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	work := t.TempDir()

	const agentID = "engine-noposture"
	token := issueToken(t, stack, agentID)
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
	})
	eng.WaitForOutput("device-posture reporting OFF", 90*time.Second)
	if !contains(eng.Output(), "DENY") {
		t.Errorf("the posture-off line does not say that a posture-requiring gateway will deny this "+
			"endpoint:\n%s", eng.Output())
	}
}
