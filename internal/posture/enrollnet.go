package posture

import (
	"fmt"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/attest"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// Enroll runs the automated network-enrollment handshake from the endpoint: submit
// the device's EK, AK, and PCR state; activate the gateway's credential challenge
// with the TPM (proving the AK genuine-TPM-resident, D184); and return the recovered
// secret. On success the gateway has enrolled the device and it can then Attest.
// subject MUST be the device's canonical pseudonym (the key the gateway will hold).
func Enroll(conn *nats.Conn, tpm *attest.TPM, ek *attest.EK, ak *attest.AK, subject string, pcrs []int) error {
	if subject == "" {
		return fmt.Errorf("posture: enroll needs a subject")
	}
	golden, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		return fmt.Errorf("posture: reading PCRs for enrollment: %w", err)
	}
	gmap := make(map[uint32][]byte, len(golden))
	for k, v := range golden {
		gmap[uint32(k)] = v
	}
	reqData, err := proto.Marshal(&corev1.AttestationEnrollRequest{
		Subject:  subject,
		EkPublic: ek.PublicKeyBytes(),
		AkPublic: ak.PublicKeyBytes(),
		AkName:   ak.Name(),
		Golden:   gmap,
	})
	if err != nil {
		return fmt.Errorf("posture: marshalling enroll request: %w", err)
	}

	// Step 1: request the credential-activation challenge.
	resp, err := conn.Request(natsx.SubjectAttestEnroll, reqData, AttestTimeout)
	if err != nil {
		return fmt.Errorf("posture: enroll challenge request: %w", err)
	}
	var challenge corev1.AttestationEnrollChallenge
	if err := proto.Unmarshal(resp.Data, &challenge); err != nil {
		return fmt.Errorf("posture: bad enroll challenge: %w", err)
	}
	if challenge.GetError() != "" {
		return fmt.Errorf("posture: enroll rejected: %s", challenge.GetError())
	}

	// Activate the challenge with the TPM to recover the secret.
	secret, err := tpm.Activate(ek, ak, &attest.Challenge{
		CredentialBlob:  challenge.GetCredentialBlob(),
		EncryptedSecret: challenge.GetEncryptedSecret(),
	})
	if err != nil {
		return fmt.Errorf("posture: activating enroll challenge: %w", err)
	}

	// Step 2: return the recovered secret.
	actData, err := proto.Marshal(&corev1.AttestationActivation{Subject: subject, Secret: secret})
	if err != nil {
		return fmt.Errorf("posture: marshalling activation: %w", err)
	}
	resp2, err := conn.Request(natsx.SubjectAttestActivate, actData, AttestTimeout)
	if err != nil {
		return fmt.Errorf("posture: activation request: %w", err)
	}
	var result corev1.AttestationEnrollResult
	if err := proto.Unmarshal(resp2.Data, &result); err != nil {
		return fmt.Errorf("posture: bad enroll result: %w", err)
	}
	if !result.GetEnrolled() {
		return fmt.Errorf("posture: enrollment refused: %s", result.GetError())
	}
	return nil
}
