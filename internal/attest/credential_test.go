package attest

import (
	"bytes"
	"testing"
)

// TestCredentialActivationRoundTrip is the happy path: a challenge built for a
// TPM's own EK and AK is activated by that TPM, recovering the issued secret —
// proving the AK is resident in a genuine TPM identified by its EK.
func TestCredentialActivationRoundTrip(t *testing.T) {
	tpm := startSWTPM(t)
	ek := mustCreateEK(t, tpm)
	defer func() { _ = tpm.FlushEK(ek) }()
	ak := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak) }()

	challenge, secret := mustChallenge(t, ek.PublicKeyBytes(), ak.Name())

	recovered, err := tpm.Activate(ek, ak, challenge)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatalf("recovered secret != issued: %x vs %x", recovered, secret)
	}
	if !VerifyActivation(secret, recovered) {
		t.Fatal("VerifyActivation false for a correct activation")
	}
}

// TestDifferentTPMCannotActivate proves the EK binds the challenge to one TPM: a
// challenge built for TPM-A's EK cannot be activated by a second, independent TPM
// (its EK cannot decrypt the seed).
func TestDifferentTPMCannotActivate(t *testing.T) {
	tpmA := startSWTPM(t)
	ekA := mustCreateEK(t, tpmA)
	defer func() { _ = tpmA.FlushEK(ekA) }()
	akA := mustCreateAK(t, tpmA)
	defer func() { _ = tpmA.Flush(akA) }()

	// The challenge is addressed to TPM-A's EK and AK name.
	challenge, secret := mustChallenge(t, ekA.PublicKeyBytes(), akA.Name())

	// A second, independent TPM with its own EK/AK.
	tpmB := startSWTPM(t)
	ekB := mustCreateEK(t, tpmB)
	defer func() { _ = tpmB.FlushEK(ekB) }()
	akB := mustCreateAK(t, tpmB)
	defer func() { _ = tpmB.Flush(akB) }()

	recovered, err := tpmB.Activate(ekB, akB, challenge)
	// TPM-B's EK cannot decrypt a seed sealed to TPM-A's EK: activation either
	// errors or yields a value that is not the issued secret. Either way the
	// server MUST NOT accept it.
	if err == nil && VerifyActivation(secret, recovered) {
		t.Fatal("a different TPM recovered the secret — binding not enforced")
	}
}

// TestSubstitutedAKFailsBinding proves the challenge is bound to the AK name: a
// challenge built for AK1's name cannot be activated with a different AK2.
func TestSubstitutedAKFailsBinding(t *testing.T) {
	tpm := startSWTPM(t)
	ek := mustCreateEK(t, tpm)
	defer func() { _ = tpm.FlushEK(ek) }()

	// AK1 only needs to exist long enough to bind the challenge to its name; the
	// challenge is built from the name bytes, so free AK1's slot before AK2.
	ak1 := mustCreateAK(t, tpm)
	challenge, secret := mustChallenge(t, ek.PublicKeyBytes(), ak1.Name())
	_ = tpm.Flush(ak1)

	ak2 := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak2) }()

	recovered, err := tpm.Activate(ek, ak2, challenge)
	if err == nil && VerifyActivation(secret, recovered) {
		t.Fatal("a substituted AK activated a challenge bound to a different AK name")
	}
}

// TestVerifyActivationRejectsMismatch is the direct, TPM-independent check of the
// server's final confirmation step: it accepts equal secrets and rejects any
// mismatch (wrong value, wrong length, empty), so a failed or forged activation
// that nonetheless returns SOME bytes is not accepted.
func TestVerifyActivationRejectsMismatch(t *testing.T) {
	secret := bytes.Repeat([]byte{0xA5}, CredentialSecretSize)
	if !VerifyActivation(secret, append([]byte(nil), secret...)) {
		t.Fatal("VerifyActivation false for equal secrets")
	}
	wrong := append([]byte(nil), secret...)
	wrong[0] ^= 0xFF
	if VerifyActivation(secret, wrong) {
		t.Fatal("VerifyActivation accepted a one-bit-different secret")
	}
	if VerifyActivation(secret, nil) || VerifyActivation(secret, secret[:8]) {
		t.Fatal("VerifyActivation accepted an empty or short secret")
	}
}

func mustCreateEK(t *testing.T, tpm *TPM) *EK {
	t.Helper()
	ek, err := tpm.CreateEK()
	if err != nil {
		t.Fatalf("create EK: %v", err)
	}
	return ek
}

func mustChallenge(t *testing.T, ekPub, akName []byte) (*Challenge, []byte) {
	t.Helper()
	c, secret, err := NewChallenge(ekPub, akName)
	if err != nil {
		t.Fatalf("new challenge: %v", err)
	}
	return c, secret
}
