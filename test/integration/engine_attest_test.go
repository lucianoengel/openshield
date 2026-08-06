//go:build integration

package integration

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// THE REAL ENDPOINT AGENT ATTESTING (CONSOLE-8e).
//
// The last of the five capabilities that lived only in the fleet SIMULATOR. Attestation is the one device
// signal that is NOT self-reported — the gateway sets `Attested` from ITS OWN verification of a TPM quote
// — which makes it the signal most worth requiring and the one whose absence is worst. With no real
// producer, a policy requiring it refused every genuine endpoint while admitting simulated ones.
//
// The orchestration is now shared (`posture.StartAgentAttestation`) rather than copied into a second
// binary, because two agents with their own TPM code is how they come to disagree about what "attested"
// means. `TestADeviceWithARealTPMSelfEnrollsAndIsAdmitted` covers the simulator against the same shared
// path, so the extraction has a regression test on both sides.

// TestTheRealEngineAttestsWithARealTPMAndIsAdmitted.
//
// BEFORE AND AFTER, for the same reason the posture scenario does it: asserting only that an attesting
// endpoint is admitted would pass against a policy that ignores attestation entirely.
func TestTheRealEngineAttestsWithARealTPMAndIsAdmitted(t *testing.T) {
	requireSWTPM(t)
	stack := StartStack(t)
	migrateStack(t, stack)
	_, enrollURL := startServer(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)
	addr := attestStack(t, stack, p, origin.addr)
	tpmAddr := startSWTPM(t)
	work := t.TempDir()

	// The agent id and the certificate CN must be the SAME identity: the gateway keys the attestation
	// verdict on the pseudonym of the identity, and the access proxy derives that pseudonym from the
	// certificate. A mismatch leaves the verdict unapplied and silent.
	const device = "engine-attest-1"
	client := attestClient(t, p, device, addr)

	// BEFORE: no endpoint is attesting, so the verifier holds nothing and the policy refuses. This is
	// the state every REAL endpoint was permanently in — the verifier fails closed by design (D85/D186),
	// so an empty verifier means a deployment that refuses everything.
	resp, err := client.Get("https://payroll/report")
	if err != nil {
		t.Fatalf("the proxy refused the connection outright: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("an UNATTESTED device was admitted through an attestation-requiring policy — without "+
			"that refusal the 'after' half below would prove nothing (status %d)", resp.StatusCode)
	}

	// The real endpoint agent starts, self-enrols its AK over the wire (credential activation proves the
	// key is TPM-resident), and attests on an interval.
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_AGENT_ID=" + device,
		// Its own database: the forward-secure ledger refuses a signer that does not hold the stored
		// chain's keys, and the gateway already opened a chain on the shared one.
		"OPENSHIELD_DSN=" + stack.DSNFor(t, "endpoint"),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "eng-signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + issueToken(t, stack, device),
		"OPENSHIELD_TPM_ADDR=" + tpmAddr,
		"OPENSHIELD_ATTEST_PCRS=0,7",
		"OPENSHIELD_ATTEST_SELF_ENROLL=1",
		"OPENSHIELD_ATTEST_INTERVAL=2s",
	})
	eng.WaitForOutput("continuous attestation ACTIVE", 90*time.Second)

	// AFTER: the same device, the same policy, the same gateway — admitted, because the gateway verified
	// a quote it asked for rather than believing anything the endpoint said about itself.
	Eventually(t, 90*time.Second, "the engine's verified TPM quote to admit it", func() bool {
		r, gerr := client.Get("https://payroll/report")
		if gerr != nil {
			return false
		}
		_ = r.Body.Close()
		return r.StatusCode == http.StatusOK
	})

	if origin.hits.Load() == 0 {
		t.Errorf("the request was admitted and never reached the internal service")
	}
	// AND THE PIPELINE KEPT RUNNING. D314's lesson: attestation on the agent's main path blocked it
	// forever against a TPM that accepts a connection and does not answer, silently disabling everything
	// else the agent does. An engine that attests and has stopped observing is not a working endpoint.
	if !contains(eng.Output(), "engine observing") {
		t.Errorf("the engine attested and never started observing — attestation must run OFF the main "+
			"path, or a slow TPM disables the whole endpoint (D314)\n%s", eng.Output())
	}
}
