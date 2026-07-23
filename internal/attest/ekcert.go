package attest

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// ParseEKPublicKey reconstructs the EK's ECDSA public key from a marshaled TPM2B_PUBLIC
// (the ek_public bytes a device submits). The EK is the same ECC-P256 shape as the AK, so
// the reconstruction is shared with ParseAKPublicKey — the server needs the EK's key to
// bind it to the EK certificate.
func ParseEKPublicKey(b []byte) (*ecdsa.PublicKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b)
	if err != nil {
		return nil, fmt.Errorf("attest: unmarshal EK public: %w", err)
	}
	return publicToECDSA(*pub)
}

// LoadEKRoots builds a manufacturer-root pool from PEM-encoded CA certificates. An empty or
// unparseable bundle is an error, never a silently empty pool — an empty pool would make
// EVERY EK cert fail to chain, and the operator must see the misconfiguration rather than
// have every device silently refused with a chain error that looks like an attack.
func LoadEKRoots(pemData []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := pemData
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attest: parsing EK root: %w", err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("attest: no CERTIFICATE blocks in EK roots bundle")
	}
	return pool, nil
}

// oidSubjectDirectoryAttributes (2.5.29.9) carries the TPM manufacturer/model/version in an
// EK certificate and is frequently marked critical; Go does not model it, so it lands in
// UnhandledCriticalExtensions and would fail Verify. It is benign for chain validation, so it
// is cleared before Verify. TCG EK certs also place vendor OIDs under the 2.23.133 arc.
var (
	oidSubjectDirectoryAttributes = asn1.ObjectIdentifier{2, 5, 29, 9}
	oidTCGArc                     = asn1.ObjectIdentifier{2, 23, 133}
)

// VerifyEKCert anchors an Endorsement Key to a genuine, manufacturer-certified TPM (R34-2).
// It performs three checks, ALL required, and returns an error if any fails so the caller
// refuses the enrollment:
//
//  1. the EK certificate parses;
//  2. it chains to the manufacturer roots pool (EK certs carry no serverAuth EKU, so any-EKU
//     is accepted, and the TCG-specific critical extensions Go does not model are cleared so a
//     legitimate vendor cert is not rejected as unparseable);
//  3. the certificate's public key EQUALS the submitted EK public key — binding the cert to
//     the EK actually being challenged, so a genuine vendor cert for a DIFFERENT EK cannot be
//     presented to launder a fabricated (e.g. swtpm) EK past the co-residence proof.
//
// It runs entirely server-side with no TPM.
func VerifyEKCert(ekCertDER []byte, roots *x509.CertPool, ekPublic []byte) error {
	if len(ekCertDER) == 0 {
		return fmt.Errorf("attest: no EK certificate presented")
	}
	if roots == nil {
		return fmt.Errorf("attest: no EK manufacturer roots configured")
	}
	cert, err := x509.ParseCertificate(ekCertDER)
	if err != nil {
		return fmt.Errorf("attest: parsing EK certificate: %w", err)
	}
	// Drop the TCG EK critical extensions Go cannot model — they are benign for chain
	// validation but would otherwise make Verify fail as "unhandled critical extension".
	kept := cert.UnhandledCriticalExtensions[:0]
	for _, oid := range cert.UnhandledCriticalExtensions {
		if oid.Equal(oidSubjectDirectoryAttributes) || tcgArc(oid) {
			continue
		}
		kept = append(kept, oid)
	}
	cert.UnhandledCriticalExtensions = kept

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("attest: EK certificate does not chain to a manufacturer root: %w", err)
	}

	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("attest: EK certificate is not an ECDSA key")
	}
	ekPub, err := ParseEKPublicKey(ekPublic)
	if err != nil {
		return fmt.Errorf("attest: reconstructing EK public: %w", err)
	}
	if !certPub.Equal(ekPub) {
		return fmt.Errorf("attest: EK certificate public key does not match the submitted EK")
	}
	return nil
}

// tcgArc reports whether oid is under the TCG 2.23.133 arc.
func tcgArc(oid asn1.ObjectIdentifier) bool {
	if len(oid) < len(oidTCGArc) {
		return false
	}
	for i := range oidTCGArc {
		if oid[i] != oidTCGArc[i] {
			return false
		}
	}
	return true
}
