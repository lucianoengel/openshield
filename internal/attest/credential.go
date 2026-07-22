package attest

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// CredentialSecretSize is the length of the random secret a challenge carries.
const CredentialSecretSize = 32

// Challenge is a TPM credential-activation challenge: a secret encrypted so that
// only the TPM holding the addressed EK's private key, together with the named
// AK, can recover it. The server sends this to an endpoint at enrollment.
type Challenge struct {
	// CredentialBlob is the TPM2B_ID_OBJECT (integrity HMAC + encrypted secret).
	CredentialBlob []byte
	// EncryptedSecret is the asymmetrically-protected seed for the EK.
	EncryptedSecret []byte
}

// NewChallenge builds a credential-activation challenge for an EK public key,
// bound to an AK name, and returns the challenge plus the expected secret the
// server retains to verify the activation. It needs no TPM: go-tpm's
// CreateCredential performs the MakeCredential crypto in pure Go.
func NewChallenge(ekPubBytes, akName []byte) (*Challenge, []byte, error) {
	ekPub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](ekPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("attest: unmarshal EK public: %w", err)
	}
	ekContents, err := ekPub.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("attest: EK public contents: %w", err)
	}
	key, err := tpm2.ImportEncapsulationKey(ekContents)
	if err != nil {
		return nil, nil, fmt.Errorf("attest: import EK as encapsulation key: %w", err)
	}

	secret := make([]byte, CredentialSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, fmt.Errorf("attest: challenge secret: %w", err)
	}

	idObject, encSecret, err := tpm2.CreateCredential(rand.Reader, key, akName, secret)
	if err != nil {
		return nil, nil, fmt.Errorf("attest: create credential: %w", err)
	}
	return &Challenge{CredentialBlob: idObject, EncryptedSecret: encSecret}, secret, nil
}

// VerifyActivation reports whether the secret an endpoint recovered by activating
// a challenge equals the one the server issued — the server's confirmation that
// the AK is bound to the genuine EK. Constant-time to avoid leaking the secret.
func VerifyActivation(expected, recovered []byte) bool {
	return subtle.ConstantTimeCompare(expected, recovered) == 1
}

// Activate runs TPM2_ActivateCredential on the endpoint: the AK is the object
// named in the challenge, and the EK decrypts the credential seed. It succeeds
// only when the EK and AK are co-resident in this TPM and the AK's name matches
// the one the challenge was bound to, returning the recovered secret. The EK's
// standard policy (PolicySecret over the endorsement hierarchy) is satisfied with
// a policy session created for the call.
func (t *TPM) Activate(ek *EK, ak *AK, c *Challenge) ([]byte, error) {
	ekAuth := tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
		_, err := tpm2.PolicySecret{
			AuthHandle:    tpm2.TPMRHEndorsement,
			PolicySession: handle,
		}.Execute(tpm)
		return err
	})

	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{
			Handle: ak.handle,
			Name:   ak.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: ek.handle,
			Name:   ek.name,
			Auth:   ekAuth,
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: c.CredentialBlob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: c.EncryptedSecret},
	}.Execute(t.tpm)
	if err != nil {
		return nil, fmt.Errorf("attest: activate credential: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}
