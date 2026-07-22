package gateway_test

import (
	"testing"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/attest"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/posture"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// enrollHarness starts the enrollment + attestation responders over embedded NATS
// against a shared verifier, and returns the verifier and an endpoint connection.
func enrollHarness(t *testing.T) (*gateway.AttestationVerifier, *nats.Conn) {
	t.Helper()
	v := gateway.NewAttestationVerifier()
	url := embeddedNATSURL(t)
	gwConn, _ := nats.Connect(url)
	t.Cleanup(gwConn.Close)
	epConn, _ := nats.Connect(url)
	t.Cleanup(epConn.Close)

	enroller := gateway.NewEnrollmentResponder(v)
	if _, err := enroller.ServeEnroll(gwConn); err != nil {
		t.Fatal(err)
	}
	if _, err := enroller.ServeActivate(gwConn); err != nil {
		t.Fatal(err)
	}
	responder := gateway.NewAttestationResponder(v)
	if _, err := responder.ServeChallenge(gwConn); err != nil {
		t.Fatal(err)
	}
	if _, err := responder.SubscribeReports(gwConn); err != nil {
		t.Fatal(err)
	}
	// Ensure the subscriptions are registered server-side before a request races them.
	if err := gwConn.Flush(); err != nil {
		t.Fatal(err)
	}
	return v, epConn
}

// TestNetworkEnrollmentEndToEnd proves a device enrolls over the wire (proving its
// AK genuine by credential activation) and can then attest — no operator file.
func TestNetworkEnrollmentEndToEnd(t *testing.T) {
	d := newDevice(t)
	ek, err := d.tpm.CreateEK()
	if err != nil {
		t.Fatalf("create EK: %v", err)
	}
	defer func() { _ = d.tpm.FlushEK(ek) }()

	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")
	extendPCR(t, d.tpm, 23, "kernel")
	const subject = "sub_device1"

	v, epConn := enrollHarness(t)

	if err := posture.Enroll(epConn, d.tpm, ek, d.ak, subject, pcrs); err != nil {
		t.Fatalf("network enroll: %v", err)
	}
	// Now enrolled, the device attests.
	if err := posture.Attest(epConn, d.tpm, d.ak, subject, pcrs); err != nil {
		t.Fatalf("attest after enroll: %v", err)
	}
	attestWaitFor(t, func() bool { return v.IsAttested(subject) })
}

// TestNetworkEnrollmentFakeDeviceRefused proves a device whose AK is on a DIFFERENT
// TPM than the EK it presents cannot activate the challenge, so enrollment is refused.
func TestNetworkEnrollmentFakeDeviceRefused(t *testing.T) {
	// TPM A supplies the EK; TPM B supplies the AK. They are not co-resident, so
	// activation cannot succeed.
	dA := newDevice(t)
	ekA, err := dA.tpm.CreateEK()
	if err != nil {
		t.Fatalf("create EK: %v", err)
	}
	defer func() { _ = dA.tpm.FlushEK(ekA) }()
	dB := newDevice(t) // its own TPM + AK

	pcrs := []int{16}
	extendPCR(t, dB.tpm, 16, "bootloader")
	const subject = "sub_fake"

	v, epConn := enrollHarness(t)

	// Present TPM-A's EK but try to activate on TPM-B (holding the AK) — the EK's
	// private half is on TPM-A, so TPM-B cannot decrypt the challenge.
	err = posture.Enroll(epConn, dB.tpm, ekA, dB.ak, subject, pcrs)
	if err == nil {
		t.Fatal("a device whose EK and AK are on different TPMs should not enroll")
	}
	if _, cerr := v.Challenge(subject); cerr == nil {
		t.Fatal("the fake device was enrolled despite failing activation")
	}
}

// TestNetworkEnrollmentBadSecretRefused drives the handshake manually with a
// genuine device but returns a TAMPERED secret in step 2 — isolating the server's
// VerifyActivation, which must refuse the enrollment.
func TestNetworkEnrollmentBadSecretRefused(t *testing.T) {
	d := newDevice(t)
	ek, err := d.tpm.CreateEK()
	if err != nil {
		t.Fatalf("create EK: %v", err)
	}
	defer func() { _ = d.tpm.FlushEK(ek) }()
	extendPCR(t, d.tpm, 16, "bootloader")
	const subject = "sub_device1"

	v, epConn := enrollHarness(t)

	// Step 1: request the challenge.
	req, _ := proto.Marshal(&corev1.AttestationEnrollRequest{
		Subject: subject, EkPublic: ek.PublicKeyBytes(), AkPublic: d.ak.PublicKeyBytes(), AkName: d.ak.Name(),
		Golden: map[uint32][]byte{16: mustGolden(t, d, 16)},
	})
	resp, err := epConn.Request(natsx.SubjectAttestEnroll, req, posture.AttestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	var ch corev1.AttestationEnrollChallenge
	_ = proto.Unmarshal(resp.Data, &ch)
	if ch.GetError() != "" {
		t.Fatalf("challenge error: %s", ch.GetError())
	}

	// The device genuinely activates (recovers the real secret) — but we send a
	// tampered secret in step 2.
	secret, err := d.tpm.Activate(ek, d.ak, &attest.Challenge{CredentialBlob: ch.GetCredentialBlob(), EncryptedSecret: ch.GetEncryptedSecret()})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	secret[0] ^= 0xFF // tamper
	act, _ := proto.Marshal(&corev1.AttestationActivation{Subject: subject, Secret: secret})
	resp2, err := epConn.Request(natsx.SubjectAttestActivate, act, posture.AttestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	var result corev1.AttestationEnrollResult
	_ = proto.Unmarshal(resp2.Data, &result)
	if result.GetEnrolled() {
		t.Fatal("a tampered activation secret must not enroll the device")
	}
	if _, cerr := v.Challenge(subject); cerr == nil {
		t.Fatal("device enrolled despite a bad activation secret")
	}
}

func mustGolden(t *testing.T, d *device, pcr int) []byte {
	t.Helper()
	m, err := d.tpm.ReadPCRs([]int{pcr})
	if err != nil {
		t.Fatal(err)
	}
	return m[pcr]
}

// TestActivateWithoutPendingEnroll proves ServeActivate refuses a subject with no
// pending enrollment (no optimistic enroll).
func TestActivateWithoutPendingEnroll(t *testing.T) {
	v, epConn := enrollHarness(t)
	data, _ := proto.Marshal(&corev1.AttestationActivation{Subject: "sub_nobody", Secret: []byte("x")})
	resp, err := epConn.Request(natsx.SubjectAttestActivate, data, posture.AttestTimeout)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var result corev1.AttestationEnrollResult
	if err := proto.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}
	if result.GetEnrolled() {
		t.Fatal("activation with no pending enrollment should not enroll")
	}
	if _, cerr := v.Challenge("sub_nobody"); cerr == nil {
		t.Fatal("sub_nobody was enrolled without a pending enroll")
	}
}
