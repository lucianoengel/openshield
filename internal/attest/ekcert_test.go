package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// synthEKPublic builds ek_public bytes (a marshaled TPM2B_PUBLIC over the ECC-P256 EK template)
// carrying pub's point, so a test can exercise the server-side EK verification without a TPM.
func synthEKPublic(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	tmpl := tpm2.ECCEKTemplate
	tmpl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: pub.X.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: pub.Y.FillBytes(make([]byte, 32))},
	})
	return tpm2.Marshal(tpm2.New2B(tmpl))
}

// manufacturerCA is a synthetic TPM-vendor root and its signing key, plus a roots pool trusting it.
type manufacturerCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newManufacturerCA(t *testing.T) manufacturerCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TPM Vendor Root"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return manufacturerCA{cert: cert, key: key, roots: pool}
}

// issueEKCert issues a leaf EK certificate over ekPub signed by the CA. extraCritical, if set, is added
// as a CRITICAL extension Go does not model (to exercise the TCG critical-extension tolerance path).
func (ca manufacturerCA) issueEKCert(t *testing.T, ekPub *ecdsa.PublicKey, extraCritical *asn1.ObjectIdentifier) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "EK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if extraCritical != nil {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: *extraCritical, Critical: true, Value: []byte{0x05, 0x00}}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, ekPub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestVerifyEKCert (R34-2): a manufacturer-chained cert bound to the submitted EK verifies; a cert that
// does not chain, one bound to a DIFFERENT key, and an absent cert are all refused.
//
// Mutations: dropping the cert.Verify chain check → the "wrong roots" case passes (FAIL); dropping the
// pubkey `.Equal` binding check → the "different key" case passes (FAIL).
func TestVerifyEKCert(t *testing.T) {
	ca := newManufacturerCA(t)
	ekKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ekPublic := synthEKPublic(t, &ekKey.PublicKey)
	certDER := ca.issueEKCert(t, &ekKey.PublicKey, nil)

	// Valid: chains to the CA and is bound to the submitted EK.
	if err := VerifyEKCert(certDER, ca.roots, ekPublic); err != nil {
		t.Fatalf("a manufacturer-chained, bound EK cert was refused: %v", err)
	}

	// Does not chain: a roots pool that does NOT contain the issuing CA.
	otherCA := newManufacturerCA(t)
	if err := VerifyEKCert(certDER, otherCA.roots, ekPublic); err == nil {
		t.Fatal("an EK cert that does not chain to the configured roots was accepted (chain check missing)")
	}

	// Wrong binding: a genuine manufacturer cert for a DIFFERENT EK key, presented with our EK's public.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherCertDER := ca.issueEKCert(t, &otherKey.PublicKey, nil)
	if err := VerifyEKCert(otherCertDER, ca.roots, ekPublic); err == nil {
		t.Fatal("a vendor cert for a DIFFERENT EK was accepted (binding check missing) — an uncertified EK could be laundered")
	}

	// Absent cert and nil roots are refused.
	if err := VerifyEKCert(nil, ca.roots, ekPublic); err == nil {
		t.Fatal("an absent EK cert was accepted")
	}
	if err := VerifyEKCert(certDER, nil, ekPublic); err == nil {
		t.Fatal("verification with no configured roots was accepted")
	}
}

// TestVerifyEKCertToleratesTCGCriticalExtensions (R34-2): real vendor EK certs carry critical extensions
// Go does not model (subjectDirectoryAttributes, the TCG arc). A cert with such a critical extension must
// still verify — otherwise a legitimate vendor cert is rejected as "unhandled critical extension".
func TestVerifyEKCertToleratesTCGCriticalExtensions(t *testing.T) {
	ca := newManufacturerCA(t)
	ekKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ekPublic := synthEKPublic(t, &ekKey.PublicKey)
	// subjectDirectoryAttributes (2.5.29.9), marked critical — the shape real EK certs use for the
	// manufacturer/model/version, which Go leaves in UnhandledCriticalExtensions.
	sda := asn1.ObjectIdentifier{2, 5, 29, 9}
	certDER := ca.issueEKCert(t, &ekKey.PublicKey, &sda)
	if err := VerifyEKCert(certDER, ca.roots, ekPublic); err != nil {
		t.Fatalf("a vendor EK cert with a critical TCG extension was refused: %v", err)
	}
}

// TestParseEKPublicKeyRoundTrip confirms synthEKPublic/ParseEKPublicKey agree, so the verification tests
// bind against the key they think they do.
func TestParseEKPublicKeyRoundTrip(t *testing.T) {
	ekKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	got, err := ParseEKPublicKey(synthEKPublic(t, &ekKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(&ekKey.PublicKey) {
		t.Fatal("ParseEKPublicKey did not reconstruct the EK public key")
	}
}

// TestLoadEKRoots covers the pool loader's fail-closed contract: a bundle with no certificates is an
// error, never a silently empty pool (which would refuse every device).
func TestLoadEKRoots(t *testing.T) {
	ca := newManufacturerCA(t)
	good := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if _, err := LoadEKRoots(good); err != nil {
		t.Fatalf("a valid roots bundle failed to load: %v", err)
	}
	if _, err := LoadEKRoots([]byte("not a pem")); err == nil {
		t.Fatal("an empty/unparseable roots bundle loaded as a silently empty pool")
	}
}
