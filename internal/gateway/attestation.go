package gateway

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/lucianoengel/openshield/internal/attest"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Attestation verification errors.
var (
	// ErrNotEnrolled is returned for a subject the verifier has no enrollment for —
	// such a device can never be attested (unattested fails closed, D85).
	ErrNotEnrolled = errors.New("gateway: device not enrolled for attestation")
	// ErrStaleNonce is returned when a report's nonce is not the fresh nonce the
	// verifier issued (or the nonce was already consumed) — the anti-replay gate.
	ErrStaleNonce = errors.New("gateway: attestation nonce is stale or already used")
)

// enrollment is a device's attestation trust anchors, established at enrollment
// (increment 2 proves the AK is genuine-TPM-resident; a golden PCR baseline is
// captured from the known-good device).
type enrollment struct {
	akPub  *ecdsa.PublicKey
	policy *attest.PCRPolicy
	// nonce is the outstanding one-shot challenge for this device, nil when none
	// is pending (issued by Challenge, consumed by VerifyReport).
	nonce []byte
	// attested is the gateway's verified conclusion for this device.
	attested bool
}

// AttestationVerifier verifies device attestation reports and tracks which devices
// the gateway has verified as hardware-attested (ZT-1). The attested state it
// exposes is set ONLY by verifying a TPM quote — never by a device's self-report.
type AttestationVerifier struct {
	mu      sync.Mutex
	devices map[string]*enrollment
}

// NewAttestationVerifier returns an empty verifier.
func NewAttestationVerifier() *AttestationVerifier {
	return &AttestationVerifier{devices: map[string]*enrollment{}}
}

// Enroll registers a device's attestation trust anchors: its AK public key (proven
// genuine-TPM-resident by credential activation, increment 2) and its golden PCR
// baseline. A device must be enrolled before it can be challenged or attested.
func (v *AttestationVerifier) Enroll(subject string, akPub *ecdsa.PublicKey, golden map[int][]byte) error {
	if subject == "" {
		return errors.New("gateway: enroll needs a subject")
	}
	if akPub == nil {
		return errors.New("gateway: enroll needs an AK public key")
	}
	policy, err := attest.NewPCRPolicy(golden)
	if err != nil {
		return fmt.Errorf("gateway: enroll baseline: %w", err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.devices[subject] = &enrollment{akPub: akPub, policy: policy}
	return nil
}

// Challenge issues a fresh one-shot nonce for an enrolled device. The device must
// answer with a quote over this exact nonce; a later quote over an old nonce is
// rejected (anti-replay). Issuing a new challenge supersedes any pending one and
// clears the device's attested state until it re-attests.
func (v *AttestationVerifier) Challenge(subject string) ([]byte, error) {
	nonce, err := attest.NewNonce()
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.devices[subject]
	if !ok {
		return nil, ErrNotEnrolled
	}
	e.nonce = nonce
	e.attested = false
	return nonce, nil
}

// VerifyReport verifies a device attestation report and, only if it passes every
// check, marks the device attested. The checks, in order: the device is enrolled;
// the report's nonce equals the outstanding challenge nonce (then consumed, so a
// replay fails); the quote verifies against the enrolled AK (increment 1); and the
// quote's PCR state matches the golden baseline (increment 3). Any failure returns
// an error and leaves the device unattested.
func (v *AttestationVerifier) VerifyReport(report *corev1.AttestationReport) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	e, ok := v.devices[report.GetSubject()]
	if !ok {
		return ErrNotEnrolled
	}
	// Anti-replay: the report must answer the outstanding nonce, which is consumed
	// on use so the same report cannot be accepted twice.
	if len(e.nonce) == 0 || subtle.ConstantTimeCompare(e.nonce, report.GetNonce()) != 1 {
		return ErrStaleNonce
	}
	nonce := e.nonce
	e.nonce = nil

	quote := &attest.Quote{
		Attest: report.GetQuoteAttest(),
		SigR:   report.GetQuoteSigR(),
		SigS:   report.GetQuoteSigS(),
	}
	vq, err := attest.VerifyQuote(e.akPub, nonce, quote)
	if err != nil {
		return err
	}
	if err := e.policy.Evaluate(vq); err != nil {
		return err
	}
	e.attested = true
	return nil
}

// IsAttested reports whether the gateway has verified the device as hardware-
// attested. Unknown or unverified devices are not attested (fail closed).
func (v *AttestationVerifier) IsAttested(subject string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.devices[subject]
	return ok && e.attested
}
