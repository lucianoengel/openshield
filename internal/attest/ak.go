package attest

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// AK is a loaded Attestation Key: a restricted ECDSA-P256 signing key resident
// in the TPM. Its private half is non-exportable (FixedTPM, SensitiveDataOrigin)
// and restricted, so the TPM will only ever sign TPM-internal structures — such
// as a quote — with it, never arbitrary attacker-chosen bytes.
//
// The AK is a created (not primary) child of a storage primary in the
// endorsement hierarchy, so each CreateAK yields a fresh, unique key — unlike a
// primary key, which is deterministically re-derived from the hierarchy seed.
type AK struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	public tpm2.TPM2BPublic
	pub    *ecdsa.PublicKey
}

// akTemplate is the public template for the AK: a restricted ECDSA-P256/SHA-256
// signing key in the endorsement hierarchy.
//
// In this increment the AK is created as a primary key in the endorsement
// hierarchy. Increment 2 restructures this so the AK is a child of the
// Endorsement Key and its residence in a genuine TPM is proven by EK-credential
// activation.
func akTemplate() tpm2.TPM2BPublic {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			Restricted:          true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
	})
}

// CreateAK creates an Attestation Key in the TPM and returns a handle to it plus
// its public key. The caller must Flush the AK when done.
func (t *TPM) CreateAK() (*AK, error) {
	// Storage primary in the endorsement hierarchy (empty auth). Increment 2
	// replaces this with the certified Endorsement Key so the AK's residence in
	// a genuine TPM is provable.
	parent, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t.tpm)
	if err != nil {
		return nil, fmt.Errorf("attest: create AK parent: %w", err)
	}
	parentAuth := tpm2.AuthHandle{
		Handle: parent.ObjectHandle,
		Name:   parent.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}

	created, err := tpm2.Create{
		ParentHandle: parentAuth,
		InPublic:     akTemplate(),
	}.Execute(t.tpm)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: parent.ObjectHandle}.Execute(t.tpm)
		return nil, fmt.Errorf("attest: create AK: %w", err)
	}

	loaded, err := tpm2.Load{
		ParentHandle: parentAuth,
		InPrivate:    created.OutPrivate,
		InPublic:     created.OutPublic,
	}.Execute(t.tpm)
	// The parent is only needed to Load the AK; once loaded the AK is usable on
	// its own, so free the parent's transient slot immediately.
	_, _ = tpm2.FlushContext{FlushHandle: parent.ObjectHandle}.Execute(t.tpm)
	if err != nil {
		return nil, fmt.Errorf("attest: load AK: %w", err)
	}

	pub, err := publicToECDSA(created.OutPublic)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(t.tpm)
		return nil, err
	}
	return &AK{
		handle: loaded.ObjectHandle,
		name:   loaded.Name,
		public: created.OutPublic,
		pub:    pub,
	}, nil
}

// Flush evicts the AK's transient handle from the TPM.
func (t *TPM) Flush(ak *AK) error {
	_, err := tpm2.FlushContext{FlushHandle: ak.handle}.Execute(t.tpm)
	return err
}

// PublicKey returns the AK's verification key.
func (ak *AK) PublicKey() *ecdsa.PublicKey { return ak.pub }

// PublicKeyBytes marshals the AK's TPM public area. A server persists these
// bytes at enrollment and later reconstructs the verification key with
// ParseAKPublicKey to check quotes — no TPM required on the server side.
func (ak *AK) PublicKeyBytes() []byte {
	return tpm2.Marshal(ak.public)
}

// ParseAKPublicKey reconstructs an ECDSA verification key from bytes produced by
// PublicKeyBytes.
func ParseAKPublicKey(b []byte) (*ecdsa.PublicKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b)
	if err != nil {
		return nil, fmt.Errorf("attest: unmarshal AK public: %w", err)
	}
	return publicToECDSA(*pub)
}

func publicToECDSA(p tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	contents, err := p.Contents()
	if err != nil {
		return nil, fmt.Errorf("attest: AK public contents: %w", err)
	}
	eccDetail, err := contents.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("attest: AK is not an ECC key: %w", err)
	}
	eccUnique, err := contents.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("attest: AK ECC point: %w", err)
	}
	pub, err := tpm2.ECDSAPub(eccDetail, eccUnique)
	if err != nil {
		return nil, fmt.Errorf("attest: AK to ECDSA: %w", err)
	}
	return pub, nil
}
