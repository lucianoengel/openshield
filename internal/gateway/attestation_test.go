package gateway_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/attest"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/pseudonym"
)

// These tests drive the real attestation crypto against a software TPM (swtpm),
// through the gateway's AttestationVerifier — the same path a live gateway uses.
// They skip where swtpm is absent, mirroring internal/attest.

func requireSWTPM(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed; skipping attestation verifier test")
	}
}

// startSWTPMForTest spawns a swtpm software TPM and returns a connected, started
// attest.TPM, reusing the exported attest.Open.
func startSWTPMForTest(t *testing.T) *attest.TPM {
	t.Helper()
	serverPort := attestFreePort(t)
	ctrlPort := attestFreePort(t)
	state := t.TempDir()
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--server", fmt.Sprintf("type=tcp,port=%d", serverPort),
		"--ctrl", fmt.Sprintf("type=tcp,port=%d", ctrlPort),
		"--tpmstate", "dir="+state, "--flags", "not-need-init")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	addr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	var tpm *attest.TPM
	for i := 0; i < 100; i++ {
		var err error
		if tpm, err = attest.Open(addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if tpm == nil {
		t.Fatalf("connect to swtpm at %s", addr)
	}
	t.Cleanup(func() { _ = tpm.Close() })
	if err := tpm.Startup(); err != nil {
		t.Fatalf("swtpm startup: %v", err)
	}
	return tpm
}

func attestFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// device is a swtpm-backed endpoint with an AK, in a known PCR state.
type device struct {
	tpm *attest.TPM
	ak  *attest.AK
}

func newDevice(t *testing.T) *device {
	t.Helper()
	requireSWTPM(t)
	tpm := startSWTPMForTest(t)
	ak, err := tpm.CreateAK()
	if err != nil {
		t.Fatalf("create AK: %v", err)
	}
	t.Cleanup(func() { _ = tpm.Flush(ak) })
	return &device{tpm: tpm, ak: ak}
}

func (d *device) report(t *testing.T, subject string, nonce []byte, pcrs []int) *corev1.AttestationReport {
	t.Helper()
	q, err := d.tpm.Quote(d.ak, nonce, pcrs)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	return &corev1.AttestationReport{
		Subject:     subject,
		Nonce:       nonce,
		QuoteAttest: q.Attest,
		QuoteSigR:   q.SigR,
		QuoteSigS:   q.SigS,
	}
}

func (d *device) golden(t *testing.T, pcrs []int) map[int][]byte {
	t.Helper()
	g, err := d.tpm.ReadPCRs(pcrs)
	if err != nil {
		t.Fatalf("read PCRs: %v", err)
	}
	return g
}

func extendPCR(t *testing.T, tpm *attest.TPM, pcr int, data string) {
	t.Helper()
	d := sha256.Sum256([]byte(data))
	if err := tpm.ExtendPCR(pcr, d[:]); err != nil {
		t.Fatalf("extend PCR %d: %v", pcr, err)
	}
}

func TestAttestationVerifierRoundTrip(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")
	extendPCR(t, d.tpm, 23, "kernel")

	v := gateway.NewAttestationVerifier()
	const subject = "sub_device1"
	if err := v.Enroll(subject, d.ak.PublicKey(), d.golden(t, pcrs)); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	nonce, err := v.Challenge(subject)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if err := v.VerifyReport(d.report(t, subject, nonce, pcrs)); err != nil {
		t.Fatalf("verify report: %v", err)
	}
	if !v.IsAttested(subject) {
		t.Fatal("device should be attested after a valid report")
	}
}

func TestAttestationReplayRejected(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")

	v := gateway.NewAttestationVerifier()
	const subject = "sub_device1"
	_ = v.Enroll(subject, d.ak.PublicKey(), d.golden(t, pcrs))
	nonce, _ := v.Challenge(subject)
	report := d.report(t, subject, nonce, pcrs)

	if err := v.VerifyReport(report); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := v.VerifyReport(report); !errors.Is(err, gateway.ErrStaleNonce) {
		t.Fatalf("replay: want ErrStaleNonce, got %v", err)
	}
}

func TestAttestationDriftNotAttested(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")
	extendPCR(t, d.tpm, 23, "kernel-v1")

	v := gateway.NewAttestationVerifier()
	const subject = "sub_device1"
	_ = v.Enroll(subject, d.ak.PublicKey(), d.golden(t, pcrs))

	extendPCR(t, d.tpm, 23, "kernel-v2-unexpected") // drift after baseline
	nonce, _ := v.Challenge(subject)
	if err := v.VerifyReport(d.report(t, subject, nonce, pcrs)); !errors.Is(err, attest.ErrPCRMismatch) {
		t.Fatalf("drift: want ErrPCRMismatch, got %v", err)
	}
	if v.IsAttested(subject) {
		t.Fatal("a drifted device must not be attested")
	}
}

func TestAttestationUnenrolledRejected(t *testing.T) {
	v := gateway.NewAttestationVerifier()
	if _, err := v.Challenge("sub_unknown"); !errors.Is(err, gateway.ErrNotEnrolled) {
		t.Fatalf("challenge unknown: want ErrNotEnrolled, got %v", err)
	}
	if err := v.VerifyReport(&corev1.AttestationReport{Subject: "sub_unknown", Nonce: []byte("x")}); !errors.Is(err, gateway.ErrNotEnrolled) {
		t.Fatalf("verify unknown: want ErrNotEnrolled, got %v", err)
	}
	if v.IsAttested("sub_unknown") {
		t.Fatal("unknown device must not be attested")
	}
}

// TestAccessProxyRequiresAttestation is the full integration: a ZT access policy
// requires a hardware-attested device; the access proxy sets DevicePosture.Attested
// from the gateway's own verification of a real swtpm quote. An attested device
// reaches the internal service; a device the gateway has not verified is denied.
func TestAccessProxyRequiresAttestation(t *testing.T) {
	const agentID = "device-42"
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")
	extendPCR(t, d.tpm, 23, "kernel")

	// Verify a real attestation for this device, keyed by the canonical pseudonym
	// the device certificate resolves to (ADR-6/IDENT-1).
	subject := pseudonym.Of(agentID)
	v := gateway.NewAttestationVerifier()
	if err := v.Enroll(subject, d.ak.PublicKey(), d.golden(t, pcrs)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	nonce, _ := v.Challenge(subject)
	if err := v.VerifyReport(d.report(t, subject, nonce, pcrs)); err != nil {
		t.Fatalf("verify report: %v", err)
	}

	up, hit := accessUpstream(t)
	pol, err := policy.New(context.Background(), "zt-attest", "1", `package openshield
import rego.v1
decision := {"action":"ALLOW","reason":"attested device","confidence":0.9} if { input.context.device_posture.attested }
decision := {"action":"BLOCK","reason":"device not hardware-attested","confidence":0.9} if { not input.context.device_posture.attested }`)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	upURL, _ := url.Parse(up.URL)
	cat.Add("127.0.0.1", upURL)
	ap := gateway.NewAccessProxy(gw, cat, 0, nil)
	ap.SetAttestationVerifier(v)

	ca := newAccessCA(t)
	addr := serveAccessTLS(t, ap, ca)

	// The attested device (cert CN = agentID → subject = the enrolled pseudonym) is admitted.
	attestedCert := ca.clientCert(t, agentID, "finance")
	if got := subjectOf(t, attestedCert); got != subject {
		t.Fatalf("device cert subject %q != enrolled %q", got, subject)
	}
	resp, err := accessClient(attestedCert, ca.pool).Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !hit.Load() {
		t.Errorf("attested device = %d (reached %v), want 200 + reached", resp.StatusCode, hit.Load())
	}

	// A different device the gateway never attested → denied (fail closed).
	otherCert := ca.clientCert(t, "device-99", "finance")
	resp2, err := accessClient(otherCert, ca.pool).Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("unattested device = %d, want 403", resp2.StatusCode)
	}
}
