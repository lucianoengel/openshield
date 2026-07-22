package attest

import (
	"crypto/rand"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// NonceSize is the length of an attestation nonce in bytes.
const NonceSize = 32

// NewNonce returns a fresh, unpredictable attestation nonce. The verifier issues
// one per attestation and remembers it until the quote returns; VerifyQuote
// rejects any quote whose qualifying data is not this exact nonce, which is what
// makes a captured old quote unusable (anti-replay).
func NewNonce() ([]byte, error) {
	n := make([]byte, NonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("attest: nonce: %w", err)
	}
	return n, nil
}

// Quote is a TPM quote plus the signature over it, ready to send to a verifier.
type Quote struct {
	// Attest is the marshaled TPMS_ATTEST structure (the quoted information).
	Attest []byte
	// SigR, SigS are the ECDSA signature over Attest.
	SigR []byte
	SigS []byte
}

// Quote produces a TPM quote over the given PCR indices (SHA-256 bank), binding
// nonce into the quote as its qualifying data. The quote is signed by the AK.
func (t *TPM) Quote(ak *AK, nonce []byte, pcrs []int) (*Quote, error) {
	rsp, err := tpm2.Quote{
		SignHandle: tpm2.AuthHandle{
			Handle: ak.handle,
			Name:   ak.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		QualifyingData: tpm2.TPM2BData{Buffer: nonce},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect:      pcrSelection(pcrs),
	}.Execute(t.tpm)
	if err != nil {
		return nil, fmt.Errorf("attest: quote: %w", err)
	}
	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("attest: quote signature is not ECDSA: %w", err)
	}
	// The TPM signs SHA-256 over the *inner* TPMS_ATTEST structure (no TPM2B
	// size prefix), so that is what we serialise and what the verifier hashes.
	attested, err := rsp.Quoted.Contents()
	if err != nil {
		return nil, fmt.Errorf("attest: quote contents: %w", err)
	}
	return &Quote{
		Attest: tpm2.Marshal(attested),
		SigR:   ecc.SignatureR.Buffer,
		SigS:   ecc.SignatureS.Buffer,
	}, nil
}

func pcrSelection(pcrs []int) tpm2.TPMLPCRSelection {
	sel := make([]uint, len(pcrs))
	for i, p := range pcrs {
		sel[i] = uint(p)
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: tpm2.PCClientCompatible.PCRs(sel...),
		}},
	}
}
