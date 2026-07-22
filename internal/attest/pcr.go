package attest

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"

	"github.com/google/go-tpm/tpm2"
)

// ErrPCRMismatch is returned when a verified quote's attested PCR state does not
// match the golden baseline — the machine's measured boot has drifted. It is
// distinct from ErrSignature/ErrNonceMismatch: the attestation itself is valid,
// but the state it attests is not the one we expect.
var ErrPCRMismatch = errors.New("attest: PCR state does not match the golden baseline")

// ReadPCRs reads the current SHA-256-bank values of the given PCR indices,
// returning index→value. An operator uses this to capture a golden baseline from
// a known-good machine.
func (t *TPM) ReadPCRs(pcrs []int) (map[int][]byte, error) {
	out := make(map[int][]byte, len(pcrs))
	// TPM2_PCRRead returns at most 8 PCRs per call; read one at a time to keep
	// the index↔value mapping unambiguous and avoid the batch-selection limit.
	for _, p := range pcrs {
		rsp, err := tpm2.PCRRead{
			PCRSelectionIn: pcrSelection([]int{p}),
		}.Execute(t.tpm)
		if err != nil {
			return nil, fmt.Errorf("attest: read PCR %d: %w", p, err)
		}
		if len(rsp.PCRValues.Digests) != 1 {
			return nil, fmt.Errorf("attest: read PCR %d: got %d values", p, len(rsp.PCRValues.Digests))
		}
		out[p] = rsp.PCRValues.Digests[0].Buffer
	}
	return out, nil
}

// ExpectedPCRDigest computes the aggregate digest a TPM quote commits to: the
// SHA-256 hash over the selected PCR values concatenated in ascending index
// order. A server compares this to a quote's attested digest without a TPM.
func ExpectedPCRDigest(values map[int][]byte, selection []int) ([]byte, error) {
	ordered := append([]int(nil), selection...)
	sort.Ints(ordered)
	h := sha256.New()
	for _, p := range ordered {
		v, ok := values[p]
		if !ok {
			return nil, fmt.Errorf("attest: no value for selected PCR %d", p)
		}
		h.Write(v)
	}
	return h.Sum(nil), nil
}

// PCRPolicy evaluates a verified quote against a golden PCR baseline captured
// from a known-good machine.
type PCRPolicy struct {
	golden map[int][]byte
}

// NewPCRPolicy builds a policy from golden per-PCR values. A policy with no
// baseline is an error, never an implicit allow.
func NewPCRPolicy(golden map[int][]byte) (*PCRPolicy, error) {
	if len(golden) == 0 {
		return nil, errors.New("attest: PCR policy needs a non-empty golden baseline")
	}
	cp := make(map[int][]byte, len(golden))
	for k, v := range golden {
		cp[k] = append([]byte(nil), v...)
	}
	return &PCRPolicy{golden: cp}, nil
}

// Evaluate reports whether a verified quote's attested PCR digest matches the
// golden baseline over the PCRs the quote covered. It returns nil when the
// machine's measured state equals golden, ErrPCRMismatch on any drift.
func (p *PCRPolicy) Evaluate(vq *VerifiedQuote) error {
	selection := selectedPCRs(vq.PCRSelection)
	expected, err := ExpectedPCRDigest(p.golden, selection)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected, vq.PCRDigest) != 1 {
		return ErrPCRMismatch
	}
	return nil
}

// selectedPCRs decodes the PCR indices set in a SHA-256-bank selection bitmap.
func selectedPCRs(sel tpm2.TPMLPCRSelection) []int {
	var pcrs []int
	for _, s := range sel.PCRSelections {
		for byteIdx, b := range s.PCRSelect {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<uint(bit)) != 0 {
					pcrs = append(pcrs, byteIdx*8+bit)
				}
			}
		}
	}
	sort.Ints(pcrs)
	return pcrs
}
