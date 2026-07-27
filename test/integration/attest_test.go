//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// HARDWARE ATTESTATION, end to end against a REAL TPM (D314).
//
// ZT-1's claim is that the gateway's `Attested` signal comes from ITS OWN verification of a TPM quote,
// never from a device's self-report. Nineteen unit tests covered the cryptography and every one of them
// SKIPPED, everywhere, for the whole life of the project: they need a software TPM, and `swtpm` was not
// installed on the build host or in CI. Nothing was wrong with them — they had simply never run, and a
// suite of skips is indistinguishable from a suite of passes in a green build log.
//
// With swtpm present they all pass. What they still cannot show is whether the FLOW is wired, and it was
// not: `posture.Enroll` — the client half of the network enrollment handshake — had NO CALLER in any
// shipped binary. The gateway served the protocol (challenge, credential activation, pre-auth tokens, EK
// anchoring: all built, all tested) and nothing spoke it. Nor could an operator take the documented
// alternative, because `attest.MarshalEnrollments` had no caller either: the enrollments FILE FORMAT had
// no tool that could write one.
//
// THAT COMBINATION IS WORSE THAN AN INERT FEATURE, because the verifier fails closed by design (D85/D186).
// An empty verifier means every device is unattested, so an operator who enabled attestation and wrote a
// policy requiring it got a deployment that refused everything — while the gateway logged that network
// enrollment was active.
//
// So these scenarios run a real software TPM, a real gateway and a real fleet agent, and assert on ACCESS
// DECISIONS rather than on log lines: whether a request is admitted is the only place the difference
// between "attested" and "logged an attestation" becomes visible.

// requireSWTPM skips when no software TPM is installed, naming what is missing.
//
// A SKIP, not a fail, because a TPM is genuinely optional infrastructure — but a LOUD one, since the
// whole reason this area went unproven for so long is that its skips were invisible.
func requireSWTPM(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm is not installed, so there is no TPM to attest to. Install the swtpm package; " +
			"this scenario needs no root and no physical TPM.")
	}
}

// startSWTPM spawns a software TPM on a TCP port and returns its address.
func startSWTPM(t *testing.T) string {
	t.Helper()
	requireSWTPM(t)
	serverPort, ctrlPort := freeTCPPort(t), freeTCPPort(t)
	state := t.TempDir()

	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--server", fmt.Sprintf("type=tcp,port=%d", serverPort),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d", ctrlPort),
		"--tpmstate", "dir="+state,
		// not-need-init so the TPM is usable without a separate startup command; the attest package
		// issues TPM2_Startup itself.
		"--flags", "not-need-init")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting swtpm: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	addr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	waitTCP(t, addr, 30*time.Second)
	return addr
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// attestedOnlyPolicy admits a request ONLY from a device the gateway has itself verified as attested.
//
// `input.context.device_posture.attested` is the gateway's OWN conclusion from verifying a quote — not a
// field the device sets. That distinction is the entire point of hardware attestation, and a policy is
// where it becomes consequential.
const attestedOnlyPolicy = `package openshield
import rego.v1
decision := {"action":"ALLOW","reason":"attested device","confidence":0.9} if {
	input.context.device_posture.attested
}
decision := {"action":"BLOCK","reason":"device is not hardware-attested","confidence":0.9} if {
	not input.context.device_posture.attested
}`

// attestStack starts an access-mode gateway with attestation enabled, and returns its address.
func attestStack(t *testing.T, stack *Stack, p *pki, originAddr string, extra ...string) string {
	t.Helper()
	work := t.TempDir()
	policyPath := filepath.Join(work, "attest.rego")
	if err := os.WriteFile(policyPath, []byte(attestedOnlyPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	m := p.serverMaterial(t)
	addr := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
	env := append([]string{
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
		"OPENSHIELD_ACCESS_CATALOG=payroll=http://" + originAddr,
		"OPENSHIELD_ATTEST=1",
		// Short, so a scenario can watch a verdict EXPIRE without waiting out the production default.
		"OPENSHIELD_ATTEST_TTL=20s",
	}, extra...)
	gw := Start(t, "openshield-gateway", env)
	gw.WaitForOutput("ZT-1 attestation transport", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)
	return addr
}

// attestClient is an HTTPS client presenting the device's certificate.
//
// The catalog resolves by HOST, so the request names the SERVICE while the dial goes to the proxy —
// which is how a client reaches it behind DNS in a deployment.
func attestClient(t *testing.T, p *pki, cn, proxyAddr string) *http.Client {
	t.Helper()
	cert := p.leafCert(t, "client", cn, "--group", "devices")
	caPEM, err := os.ReadFile(p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the CA certificate did not parse")
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert}, RootCAs: pool,
				ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, proxyAddr)
			},
		},
	}
}

// TestAnUnattestedDeviceIsRefused is the fail-closed half, and it runs FIRST because it is what makes
// the success below mean anything: a gateway that admitted everyone would satisfy the positive case.
func TestAnUnattestedDeviceIsRefused(t *testing.T) {
	requireSWTPM(t)
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)
	addr := attestStack(t, stack, p, origin.addr)

	client := attestClient(t, p, "laptop-unenrolled", addr)
	resp, err := client.Get("https://payroll/report")
	if err != nil {
		t.Fatalf("requesting through the access proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a device that has NEVER ATTESTED was admitted (status %d). The verifier is empty, so "+
			"every device is unattested and a policy requiring attestation must refuse — failing OPEN "+
			"here would mean the strongest device signal the product has is satisfied by not having a "+
			"TPM at all", resp.StatusCode)
	}
	if origin.hits.Load() != 0 {
		t.Errorf("the origin received %d request(s) from an unattested device. A 403 to the client "+
			"proves the gateway answered; only an untouched origin proves the request did not arrive",
			origin.hits.Load())
	}
}

// startAttestingAgent enrols the agent's IDENTITY with the control plane, then starts it attesting.
//
// The identity enrollment is not scaffolding to skip past: the agent refuses to start without it (D283's
// trust bootstrap), and it is the right refusal. Hardware attestation answers "is this machine in a state
// I recognise"; it says nothing about WHICH machine is talking, and a device that attested beautifully
// under an identity it had never proved would be a stronger signal attached to a weaker claim.
func startAttestingAgent(t *testing.T, stack *Stack, enrollURL, device, tpmAddr string, extra ...string) *Process {
	t.Helper()
	return Start(t, "openshield-fleet-agent", append([]string{
		"OPENSHIELD_AGENT_ID=" + device,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + issueToken(t, stack, device),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_TPM_ADDR=" + tpmAddr,
		"OPENSHIELD_ATTEST_PCRS=0,7",
		"OPENSHIELD_ATTEST_SELF_ENROLL=1",
		"OPENSHIELD_ATTEST_INTERVAL=2s",
		"OPENSHIELD_HEARTBEAT=1s",
	}, extra...))
}

// TestADeviceWithARealTPMSelfEnrollsAndIsAdmitted is the whole chain: a real TPM, credential activation
// over the wire, a verified quote, and an access decision that changes because of it.
func TestADeviceWithARealTPMSelfEnrollsAndIsAdmitted(t *testing.T) {
	requireSWTPM(t)
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)
	addr := attestStack(t, stack, p, origin.addr)
	tpmAddr := startSWTPM(t)

	// The agent id and the certificate CN must be the SAME identity, because the gateway keys posture on
	// the pseudonym of the identity and the access proxy derives that pseudonym from the certificate. A
	// mismatch would attest a device that no request is ever attributed to — the scenario would pass its
	// enrollment step and fail its access step, for a reason that looks like an attestation failure.
	const device = "laptop-attested"
	_, enrollURL := startServer(t, stack)
	agent := startAttestingAgent(t, stack, enrollURL, device, tpmAddr)
	// The agent SAYS it enrolled; that is an announcement, so it is a waypoint and not the assertion.
	agent.WaitForOutput("self-enrolled with the gateway", 90*time.Second)

	client := attestClient(t, p, device, addr)
	deadline := time.Now().Add(90 * time.Second)
	var last int
	for time.Now().Before(deadline) {
		resp, err := client.Get("https://payroll/report")
		if err != nil {
			t.Fatalf("requesting through the access proxy: %v", err)
		}
		last = resp.StatusCode
		_ = resp.Body.Close()
		if last == http.StatusOK {
			break
		}
		time.Sleep(time.Second)
	}
	if last != http.StatusOK {
		t.Fatalf("a device with a real TPM self-enrolled and attested, and the access proxy still "+
			"refused it (last status %d).\nagent:\n%s", last, agent.Output())
	}
	if origin.hits.Load() == 0 {
		t.Error("the proxy returned 200 and the origin was never reached — the request was answered by " +
			"something other than the service it was for")
	}
}

// TestAttestationExpiresWhenADeviceStopsAttesting is R34-1's property, and the one that makes attestation
// CONTINUOUS rather than a one-time gate.
//
// A device that attested once and then went quiet may have been rebooted into anything. The verdict is
// therefore a lease, and this proves the lease actually lapses — a TTL that is stored and never enforced
// looks identical for as long as the device keeps attesting, which is exactly when nobody is looking.
func TestAttestationExpiresWhenADeviceStopsAttesting(t *testing.T) {
	requireSWTPM(t)
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)
	addr := attestStack(t, stack, p, origin.addr)
	tpmAddr := startSWTPM(t)

	const device = "laptop-goes-quiet"
	_, enrollURL := startServer(t, stack)
	agent := startAttestingAgent(t, stack, enrollURL, device, tpmAddr)
	agent.WaitForOutput("self-enrolled with the gateway", 90*time.Second)

	client := attestClient(t, p, device, addr)
	get := func() int {
		t.Helper()
		resp, err := client.Get("https://payroll/report")
		if err != nil {
			t.Fatalf("requesting through the access proxy: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	deadline := time.Now().Add(90 * time.Second)
	for get() != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatalf("the device never became attested, so this scenario cannot show a verdict "+
				"EXPIRING\nagent:\n%s", agent.Output())
		}
		time.Sleep(time.Second)
	}

	// STOP ATTESTING. Killing the agent is the honest simulation: the device has not been revoked, it
	// has simply gone silent, which is what a machine that was powered off and tampered with looks like
	// from here.
	agent.Stop()

	// The TTL is 20s; allow generously more before concluding it does not expire at all.
	expired := time.Now().Add(90 * time.Second)
	for time.Now().Before(expired) {
		if get() != http.StatusOK {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Errorf("the device stopped attesting %s ago and is STILL admitted with a %ds TTL. An attestation "+
		"verdict that never lapses is a one-time gate wearing continuous clothing: a machine could attest "+
		"once at enrollment, be rebooted into anything, and keep its trusted status indefinitely",
		time.Since(expired.Add(-90*time.Second)), 20)
}

// PRE-AUTHORIZATION AND EK ANCHORING (D317) — the two guards that decide WHICH devices may self-enrol.
//
// Self-enrollment, which D314 made possible, lets a device assert its own identity to the control plane.
// R34-2 added two constraints on that: an operator-issued single-use token, and a requirement that the
// device's Endorsement Key chain to a TPM manufacturer root. Both were built, unit-tested and enforced
// server-side.
//
// THE TOKEN GUARD WAS UNSATISFIABLE. `EnrollToken` had no producer anywhere in the tree, so a gateway
// that turned pre-authorization ON could not be enrolled by any shipped client: the request arrived with
// an empty token and was refused, correctly and permanently. That is worse than an unenforced control —
// enabling it did not make enrollment stricter, it made the capability impossible, so the only way to run
// the product was with its own guard switched off.

// TestAPreAuthorizedDeviceEnrollsAndAnUnauthorizedOneDoesNot.
//
// BOTH HALVES IN ONE SCENARIO, deliberately. A gateway that refused every enrollment would satisfy the
// negative on its own — and that was the ACTUAL STATE before D317, so a negative-only test here would
// have passed against the bug it exists to catch. This is the lesson D316 paid for with six vacuous
// OIDC negatives.
func TestAPreAuthorizedDeviceEnrollsAndAnUnauthorizedOneDoesNot(t *testing.T) {
	requireSWTPM(t)
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)
	const token = "operator-issued-token-1"
	addr := attestStack(t, stack, p, origin.addr, "OPENSHIELD_ENROLL_PREAUTH_TOKENS="+token)
	_, enrollURL := startServer(t, stack)

	// THE POSITIVE: a device presenting the operator's token enrols and becomes attested.
	good := startAttestingAgent(t, stack, enrollURL, "laptop-authorized", startSWTPM(t),
		"OPENSHIELD_ENROLL_PREAUTH_TOKEN="+token)
	good.WaitForOutput("self-enrolled with the gateway", 90*time.Second)

	client := attestClient(t, p, "laptop-authorized", addr)
	deadline := time.Now().Add(90 * time.Second)
	var last int
	for time.Now().Before(deadline) {
		if last = get(t, client, "https://payroll/report"); last == http.StatusOK {
			break
		}
		time.Sleep(time.Second)
	}
	if last != http.StatusOK {
		t.Fatalf("a device presenting the operator's pre-auth token was not admitted (last %d). Until "+
			"D317 nothing could SEND a token at all, so turning the guard on made enrollment impossible "+
			"rather than stricter\n%s", last, good.Output())
	}

	// THE NEGATIVE: the same everything, no token.
	bad := startAttestingAgent(t, stack, enrollURL, "laptop-unauthorized", startSWTPM(t))
	bad.WaitForOutput("self-enrollment did not complete", 90*time.Second)
	if contains(bad.Output(), "self-enrolled with the gateway") {
		t.Errorf("a device with NO pre-auth token enrolled. The token is what stops any machine with a "+
			"co-resident TPM from adding itself to the fleet's trusted set\n%s", bad.Output())
	}
	if code := get(t, attestClient(t, p, "laptop-unauthorized", addr), "https://payroll/report"); code == http.StatusOK {
		t.Error("an unenrolled device was admitted by an attestation-requiring policy")
	}
}

// TestEKCertificateAnchoringRefusesAFabricatedEK.
//
// The gateway warns, when anchoring is off, that "a fabricated EK (incl. swtpm) passes enrollment" — and
// that warning is exactly what makes this testable: a software TPM has no manufacturer-signed EK
// certificate, so with a real root bundle configured, swtpm is precisely the thing that must be refused.
//
// The honest limit this scenario CANNOT cover: it proves an uncertified EK is refused, not that a
// genuinely certified one is accepted, because that needs real TPM vendor hardware. The positive half is
// the scenario above, run without anchoring — which is why both live here rather than only the negative.
func TestEKCertificateAnchoringRefusesAFabricatedEK(t *testing.T) {
	requireSWTPM(t)
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)
	work := t.TempDir()

	// A real, well-formed root bundle that simply does not include swtpm's (nonexistent) issuer. Using
	// the fleet CA is deliberate: an EMPTY or malformed file would be refused at startup for parsing
	// reasons, which would prove nothing about the chain check.
	roots := filepath.Join(work, "ek-roots.pem")
	caPEM, err := os.ReadFile(p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(roots, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	addr := attestStack(t, stack, p, origin.addr, "OPENSHIELD_EK_ROOTS="+roots)
	_ = addr
	_, enrollURL := startServer(t, stack)

	agent := startAttestingAgent(t, stack, enrollURL, "laptop-fabricated-ek", startSWTPM(t))
	agent.WaitForOutput("self-enrollment did not complete", 90*time.Second)
	if contains(agent.Output(), "self-enrolled with the gateway") {
		t.Errorf("a device with a FABRICATED EK enrolled while manufacturer anchoring was required. "+
			"Credential activation proves the AK lives in the same TPM as the EK; only the EK certificate "+
			"proves that TPM is a real one, so without this check an emulator joins the fleet\n%s",
			agent.Output())
	}
}
