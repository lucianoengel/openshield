package attest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// extendPCR extends a writable PCR (e.g. 16 debug, 23 app-specific) with the
// SHA-256 digest of data, simulating a measured-boot event.
func extendPCR(t *testing.T, tpm *TPM, pcr int, data string) {
	t.Helper()
	d := sha256.Sum256([]byte(data))
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(pcr),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{{
				HashAlg: tpm2.TPMAlgSHA256,
				Digest:  d[:],
			}},
		},
	}.Execute(tpm.tpm)
	if err != nil {
		t.Fatalf("extend PCR %d: %v", pcr, err)
	}
}

// quoteVerified quotes the given PCRs under ak and returns the verified quote.
func quoteVerified(t *testing.T, tpm *TPM, ak *AK, pcrs []int) *VerifiedQuote {
	t.Helper()
	nonce := mustNonce(t)
	q, err := tpm.Quote(ak, nonce, pcrs)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	vq, err := VerifyQuote(ak.PublicKey(), nonce, q)
	if err != nil {
		t.Fatalf("verify quote: %v", err)
	}
	return vq
}

// TestExpectedDigestMatchesQuote proves the pure-Go expected-digest computation
// equals the digest the TPM actually signs into a quote for the same PCR state.
func TestExpectedDigestMatchesQuote(t *testing.T) {
	tpm := startSWTPM(t)
	ak := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak) }()

	pcrs := []int{16, 23}
	extendPCR(t, tpm, 16, "bootloader-v1")
	extendPCR(t, tpm, 23, "kernel-v1")

	golden, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		t.Fatalf("read PCRs: %v", err)
	}
	vq := quoteVerified(t, tpm, ak, pcrs)

	expected, err := ExpectedPCRDigest(golden, pcrs)
	if err != nil {
		t.Fatalf("expected digest: %v", err)
	}
	if !bytes.Equal(expected, vq.PCRDigest) {
		t.Fatalf("expected digest %x != quoted digest %x", expected, vq.PCRDigest)
	}
}

// TestPCRPolicyCompliantThenDrift proves the policy: the golden state is
// compliant, and after the machine's PCR state drifts the same policy rejects
// the new quote.
func TestPCRPolicyCompliantThenDrift(t *testing.T) {
	tpm := startSWTPM(t)
	ak := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak) }()

	pcrs := []int{16, 23}
	extendPCR(t, tpm, 16, "bootloader-v1")
	extendPCR(t, tpm, 23, "kernel-v1")

	golden, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		t.Fatalf("read PCRs: %v", err)
	}
	policy, err := NewPCRPolicy(golden)
	if err != nil {
		t.Fatalf("new policy: %v", err)
	}

	// Golden state: compliant.
	if err := policy.Evaluate(quoteVerified(t, tpm, ak, pcrs)); err != nil {
		t.Fatalf("golden state should be compliant: %v", err)
	}

	// Drift: a later measurement changes PCR 23 (e.g. a kernel update).
	extendPCR(t, tpm, 23, "kernel-v2-unexpected")
	if err := policy.Evaluate(quoteVerified(t, tpm, ak, pcrs)); !errors.Is(err, ErrPCRMismatch) {
		t.Fatalf("drifted state: want ErrPCRMismatch, got %v", err)
	}
}

// TestPCRPolicyRejectsEmptyBaseline proves a policy cannot be built with no
// baseline (which would be an implicit allow).
func TestPCRPolicyRejectsEmptyBaseline(t *testing.T) {
	if _, err := NewPCRPolicy(nil); err == nil {
		t.Fatal("NewPCRPolicy(nil) should error")
	}
	if _, err := NewPCRPolicy(map[int][]byte{}); err == nil {
		t.Fatal("NewPCRPolicy(empty) should error")
	}
}
