package gateway

import (
	"fmt"
	"os"

	"github.com/lucianoengel/openshield/internal/attest"
)

// LoadAttestationEnrollments reads a device-enrollment file and enrolls each
// record into the verifier, returning the count enrolled. A malformed or
// incomplete record fails the whole load — never a silent skip: a silently
// dropped device would be treated as unenrolled and denied while the operator
// believes it was loaded, so the error surfaces at load time (like the posture
// roster). The verifier is populated only for records that all validate.
func LoadAttestationEnrollments(v *AttestationVerifier, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("gateway: reading attestation enrollments: %w", err)
	}
	records, err := attest.ParseEnrollments(data)
	if err != nil {
		return 0, err
	}
	if len(records) == 0 {
		return 0, fmt.Errorf("gateway: attestation enrollment file %q is empty", path)
	}
	// Validate all before enrolling any, so a bad record does not leave a
	// partially-populated verifier.
	for _, r := range records {
		if err := r.Validate(); err != nil {
			return 0, err
		}
	}
	for _, r := range records {
		akPub, err := attest.ParseAKPublicKey(r.AKPublic)
		if err != nil {
			return 0, err // already validated, but keep the fail-closed contract explicit
		}
		if err := v.Enroll(r.Subject, akPub, r.Golden); err != nil {
			return 0, fmt.Errorf("gateway: enrolling %q: %w", r.Subject, err)
		}
	}
	return len(records), nil
}
