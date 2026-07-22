package attest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// AttestationEnrollment is a device's attestation trust anchors, captured for
// distribution to a gateway: its pseudonymous subject, its AK public key (proven
// genuine-TPM-resident by credential activation at capture time, D184), and its
// golden PCR baseline. Loaded into an attestation verifier, it lets the device
// attest without the gateway ever touching a TPM.
type AttestationEnrollment struct {
	Subject  string
	AKPublic []byte
	Golden   map[int][]byte
}

// Validate rejects an incomplete or malformed record: the enrollment must have a
// subject, an AK public key that parses, and a non-empty golden baseline. A record
// that fails Validate must never be loaded (fail closed) rather than silently
// treated as unenrolled.
func (e AttestationEnrollment) Validate() error {
	if e.Subject == "" {
		return fmt.Errorf("attest: enrollment has no subject")
	}
	if _, err := ParseAKPublicKey(e.AKPublic); err != nil {
		return fmt.Errorf("attest: enrollment %q has an unparseable AK public key: %w", e.Subject, err)
	}
	if len(e.Golden) == 0 {
		return fmt.Errorf("attest: enrollment %q has an empty PCR baseline", e.Subject)
	}
	return nil
}

// jsonEnrollment is the on-disk shape: base64 AK bytes and hex PCR values keep the
// file a readable, diff-able, operator-editable text file.
type jsonEnrollment struct {
	Subject  string            `json:"subject"`
	AKPublic string            `json:"ak_public"`
	PCRs     map[string]string `json:"pcrs"`
}

type jsonEnrollmentFile struct {
	Enrollments []jsonEnrollment `json:"enrollments"`
}

// MarshalEnrollments serializes enrollment records to the JSON file format.
func MarshalEnrollments(records []AttestationEnrollment) ([]byte, error) {
	file := jsonEnrollmentFile{Enrollments: make([]jsonEnrollment, 0, len(records))}
	for _, r := range records {
		pcrs := make(map[string]string, len(r.Golden))
		for idx, v := range r.Golden {
			pcrs[fmt.Sprintf("%d", idx)] = hex.EncodeToString(v)
		}
		file.Enrollments = append(file.Enrollments, jsonEnrollment{
			Subject:  r.Subject,
			AKPublic: base64.StdEncoding.EncodeToString(r.AKPublic),
			PCRs:     pcrs,
		})
	}
	// Stable order for a diff-able file.
	sort.Slice(file.Enrollments, func(i, j int) bool {
		return file.Enrollments[i].Subject < file.Enrollments[j].Subject
	})
	return json.MarshalIndent(file, "", "  ")
}

// ParseEnrollments parses the JSON enrollment file. It decodes the encoding only;
// callers Validate each record before use.
func ParseEnrollments(data []byte) ([]AttestationEnrollment, error) {
	var file jsonEnrollmentFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("attest: parsing enrollments: %w", err)
	}
	records := make([]AttestationEnrollment, 0, len(file.Enrollments))
	for _, je := range file.Enrollments {
		akPub, err := base64.StdEncoding.DecodeString(je.AKPublic)
		if err != nil {
			return nil, fmt.Errorf("attest: enrollment %q has bad base64 AK: %w", je.Subject, err)
		}
		golden := make(map[int][]byte, len(je.PCRs))
		for k, v := range je.PCRs {
			var idx int
			if _, err := fmt.Sscanf(k, "%d", &idx); err != nil {
				return nil, fmt.Errorf("attest: enrollment %q has bad PCR index %q: %w", je.Subject, k, err)
			}
			b, err := hex.DecodeString(v)
			if err != nil {
				return nil, fmt.Errorf("attest: enrollment %q has bad hex PCR %d: %w", je.Subject, idx, err)
			}
			golden[idx] = b
		}
		records = append(records, AttestationEnrollment{Subject: je.Subject, AKPublic: akPub, Golden: golden})
	}
	return records, nil
}
