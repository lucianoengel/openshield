package posture

import (
	"fmt"

	"github.com/lucianoengel/openshield/internal/attest"
)

// BuildEnrollment captures a device's attestation trust anchors into a
// distributable record: its AK public key and its golden PCR baseline over the
// given PCRs, under subject (the device's canonical pseudonym). An operator
// collects these records into the gateway's enrollment file.
//
// The AK should be one proven genuine-TPM-resident by credential activation
// (attest.Activate, D184) before its record is trusted; the file-distribution
// flow trusts the operator's capture of that proven AK.
func BuildEnrollment(tpm *attest.TPM, ak *attest.AK, subject string, pcrs []int) (attest.AttestationEnrollment, error) {
	if subject == "" {
		return attest.AttestationEnrollment{}, fmt.Errorf("posture: enrollment needs a subject")
	}
	golden, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		return attest.AttestationEnrollment{}, fmt.Errorf("posture: reading golden PCRs: %w", err)
	}
	record := attest.AttestationEnrollment{
		Subject:  subject,
		AKPublic: ak.PublicKeyBytes(),
		Golden:   golden,
	}
	if err := record.Validate(); err != nil {
		return attest.AttestationEnrollment{}, err
	}
	return record, nil
}
