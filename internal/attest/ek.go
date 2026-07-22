package attest

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// EK is a loaded Endorsement Key: the TPM's manufacturer-rooted decryption key,
// unique to the device. In production it is accompanied by an EK certificate
// chaining to the TPM vendor's CA; here it anchors the AK↔TPM binding via
// credential activation. Its standard auth is a policy (PolicySecret over the
// endorsement hierarchy), which Activate satisfies with a policy session.
type EK struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	public tpm2.TPM2BPublic
}

// CreateEK creates an Endorsement Key from the standard ECC-P256 EK template in
// the endorsement hierarchy. The caller must FlushEK when done.
func (t *TPM) CreateEK() (*EK, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(t.tpm)
	if err != nil {
		return nil, fmt.Errorf("attest: create EK: %w", err)
	}
	return &EK{
		handle: rsp.ObjectHandle,
		name:   rsp.Name,
		public: rsp.OutPublic,
	}, nil
}

// FlushEK evicts the EK's transient handle from the TPM.
func (t *TPM) FlushEK(ek *EK) error {
	_, err := tpm2.FlushContext{FlushHandle: ek.handle}.Execute(t.tpm)
	return err
}

// PublicKeyBytes marshals the EK's TPM public area. The server loads these bytes
// to build a credential-activation challenge addressed to this specific TPM.
func (ek *EK) PublicKeyBytes() []byte {
	return tpm2.Marshal(ek.public)
}
