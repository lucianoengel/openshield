package provision_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
	"github.com/lucianoengel/openshield/internal/provision"
	"github.com/lucianoengel/openshield/internal/transport/tlsconf"
)

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(certPEM)
	if b == nil {
		t.Fatal("cert PEM did not decode")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// 3.1 — an issued leaf verifies against the CA (real x509), carries the right OU
// role, and loads through the TLS loader; an invalid role is rejected.
func TestIssuedCertVerifiesAndCarriesRole(t *testing.T) {
	caCert, caKey, err := provision.InitCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := provision.IssueCert(caCert, caKey, "alice", provision.RoleOperator, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	// Verifies against the CA.
	leaf := parseLeaf(t, certPEM)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		t.Fatal("CA PEM not usable")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("issued leaf does not verify against the CA: %v", err)
	}

	// Carries the operator role in OU.
	if got := leaf.Subject.OrganizationalUnit; len(got) != 1 || got[0] != provision.RoleOperator {
		t.Fatalf("leaf OU = %v, want [operator]", got)
	}

	// Loads through the real TLS loader.
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	cPath := filepath.Join(dir, "cert.pem")
	kPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(caPath, caCert, 0o644)
	_ = os.WriteFile(cPath, certPEM, 0o644)
	_ = os.WriteFile(kPath, keyPEM, 0o600)
	if _, err := tlsconf.Load(caPath, cPath, kPath); err != nil {
		t.Fatalf("provisioned cert did not load via tlsconf.Load: %v", err)
	}

	// An invalid role is rejected, not issued.
	if _, _, err := provision.IssueCert(caCert, caKey, "x", "superuser", nil); err == nil {
		t.Fatal("an unknown role was issued a certificate")
	}
}

// 3.3 — a provisioned escrow keypair round-trips through the enforcer: seal with
// the public key, recover with the private key, and a wrong private key fails.
func TestProvisionedEscrowKeypairRoundTrips(t *testing.T) {
	pub, priv, err := provision.EscrowKeypair()
	if err != nil {
		t.Fatal(err)
	}
	enf, err := encryptlocal.WithEscrowKey(pub)
	if err != nil {
		t.Fatalf("enforcer rejected the provisioned public key: %v", err)
	}

	dir := t.TempDir()
	f := filepath.Join(dir, "secret.txt")
	plaintext := []byte("the exact original bytes")
	_ = os.WriteFile(f, plaintext, 0o600)
	if err := enf.EnforceTarget(nil, nil, f); err != nil {
		t.Fatal(err)
	}
	sealed, _ := os.ReadFile(f)

	got, err := encryptlocal.DecryptEscrow(pub, priv, sealed)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("provisioned escrow keypair did not round-trip: %v", err)
	}
	_, otherPriv, _ := provision.EscrowKeypair()
	if _, err := encryptlocal.DecryptEscrow(pub, otherPriv, sealed); err == nil {
		t.Fatal("a different private key recovered the escrow blob")
	}
}
