package attest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// Verification errors. Callers can match on these to distinguish a stale/replayed
// quote (ErrNonceMismatch) from a forged or wrong-key one (ErrSignature).
var (
	// ErrNotAQuote is returned when the attest blob is not a genuine
	// TPM-generated quote structure.
	ErrNotAQuote = errors.New("attest: not a TPM quote")
	// ErrNonceMismatch is returned when the quote's qualifying data is not the
	// nonce the verifier issued — the anti-replay gate.
	ErrNonceMismatch = errors.New("attest: quote nonce mismatch")
	// ErrSignature is returned when the quote signature does not verify under the
	// expected AK public key.
	ErrSignature = errors.New("attest: quote signature invalid")
)

// VerifiedQuote is the trustworthy result of a verified quote: the digest of the
// attested PCRs, which a later policy layer (increment 3) checks against an
// expected measured-boot state.
type VerifiedQuote struct {
	// PCRDigest is the TPM's digest over the selected PCR values.
	PCRDigest []byte
	// PCRSelection is the set of PCRs the quote covered.
	PCRSelection tpm2.TPMLPCRSelection
}

// VerifyQuote verifies a TPM quote server-side against a stored AK public key.
// It rejects the quote unless all of:
//   - the blob is a genuine TPM-generated quote structure,
//   - its qualifying data equals the exact nonce the verifier issued (freshness),
//   - the signature is valid under akPub.
//
// Only when every check passes does it return the attested PCR digest.
func VerifyQuote(akPub *ecdsa.PublicKey, nonce []byte, q *Quote) (*VerifiedQuote, error) {
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](q.Attest)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotAQuote, err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue {
		return nil, fmt.Errorf("%w: bad magic", ErrNotAQuote)
	}
	if attest.Type != tpm2.TPMSTAttestQuote {
		return nil, fmt.Errorf("%w: type %v", ErrNotAQuote, attest.Type)
	}

	// Anti-replay: the quote must carry the nonce this verifier issued. A
	// captured old quote carries a different nonce and is rejected here.
	if subtle.ConstantTimeCompare(attest.ExtraData.Buffer, nonce) != 1 {
		return nil, ErrNonceMismatch
	}

	// The TPM signs SHA-256 over the marshaled attest structure.
	digest := sha256.Sum256(q.Attest)
	r := new(big.Int).SetBytes(q.SigR)
	s := new(big.Int).SetBytes(q.SigS)
	if !ecdsa.Verify(akPub, digest[:], r, s) {
		return nil, ErrSignature
	}

	quoteInfo, err := attest.Attested.Quote()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotAQuote, err)
	}
	return &VerifiedQuote{
		PCRDigest:    quoteInfo.PCRDigest.Buffer,
		PCRSelection: quoteInfo.PCRSelect,
	}, nil
}
