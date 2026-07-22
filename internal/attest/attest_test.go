package attest

import (
	"errors"
	"testing"
)

// TestConnectAndStartup is the harness sanity check: swtpm spawns and
// TPM2_Startup succeeds via the go-tpm transport.
func TestConnectAndStartup(t *testing.T) {
	startSWTPM(t) // fails the test if connect/startup errors
}

// TestAKPublicKeyRoundTrip proves a server holding no TPM can reconstruct the AK
// verification key from the marshaled public bytes the agent sends at enrollment.
func TestAKPublicKeyRoundTrip(t *testing.T) {
	tpm := startSWTPM(t)
	ak := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak) }()

	parsed, err := ParseAKPublicKey(ak.PublicKeyBytes())
	if err != nil {
		t.Fatalf("parse AK public: %v", err)
	}
	if !parsed.Equal(ak.PublicKey()) {
		t.Fatal("round-tripped AK public key does not match the original")
	}
	// The AK template is FixedTPM + Restricted + SensitiveDataOrigin, so the
	// private half is non-exportable: what the agent sends is a TPM public area,
	// and reconstructing a usable *verification* key from it (above) is all a
	// server ever gets.
	if !attestTemplateIsFixedTPM(t) {
		t.Fatal("AK template is not FixedTPM/Restricted — private half could be exportable")
	}
}

func attestTemplateIsFixedTPM(t *testing.T) bool {
	t.Helper()
	tmpl := akTemplate()
	c, err := tmpl.Contents()
	if err != nil {
		t.Fatalf("AK template contents: %v", err)
	}
	a := c.ObjectAttributes
	return a.FixedTPM && a.Restricted && a.SensitiveDataOrigin
}

// TestQuoteVerifyRoundTrip is the happy path: a quote over a fresh nonce verifies
// against the correct AK public key and yields a PCR digest.
func TestQuoteVerifyRoundTrip(t *testing.T) {
	tpm := startSWTPM(t)
	ak := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak) }()

	nonce := mustNonce(t)
	q, err := tpm.Quote(ak, nonce, []int{0, 7})
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	vq, err := VerifyQuote(ak.PublicKey(), nonce, q)
	if err != nil {
		t.Fatalf("verify valid quote: %v", err)
	}
	if len(vq.PCRDigest) == 0 {
		t.Fatal("verified quote returned an empty PCR digest")
	}
}

// TestReplayedQuoteRejected proves the nonce is anti-replay: a quote taken over
// nonce A does not verify when the verifier expected a different nonce B.
func TestReplayedQuoteRejected(t *testing.T) {
	tpm := startSWTPM(t)
	ak := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak) }()

	nonceA := mustNonce(t)
	q, err := tpm.Quote(ak, nonceA, []int{0, 7})
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	nonceB := mustNonce(t) // a different attestation's nonce
	if _, err := VerifyQuote(ak.PublicKey(), nonceB, q); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("replayed quote: want ErrNonceMismatch, got %v", err)
	}
}

// TestTamperedSignatureRejected proves a quote with an altered signature fails.
func TestTamperedSignatureRejected(t *testing.T) {
	tpm := startSWTPM(t)
	ak := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak) }()

	nonce := mustNonce(t)
	q, err := tpm.Quote(ak, nonce, []int{0, 7})
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	q.SigR[0] ^= 0xFF // flip a signature byte
	if _, err := VerifyQuote(ak.PublicKey(), nonce, q); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered signature: want ErrSignature, got %v", err)
	}
}

// TestWrongAKRejected proves a quote is bound to the AK that signed it: verifying
// it against a different AK's public key fails.
func TestWrongAKRejected(t *testing.T) {
	tpm := startSWTPM(t)
	ak1 := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak1) }()
	ak2 := mustCreateAK(t, tpm)
	defer func() { _ = tpm.Flush(ak2) }()

	nonce := mustNonce(t)
	q, err := tpm.Quote(ak1, nonce, []int{0, 7})
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	if _, err := VerifyQuote(ak2.PublicKey(), nonce, q); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong AK: want ErrSignature, got %v", err)
	}
}

func mustCreateAK(t *testing.T, tpm *TPM) *AK {
	t.Helper()
	ak, err := tpm.CreateAK()
	if err != nil {
		t.Fatalf("create AK: %v", err)
	}
	return ak
}

func mustNonce(t *testing.T) []byte {
	t.Helper()
	n, err := NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return n
}
