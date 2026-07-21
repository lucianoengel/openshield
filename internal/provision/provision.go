// Package provision issues the credentials the security stack needs — a local CA,
// role-tagged agent/operator certificates (D58), and escrow keypairs (D59) — so
// mutual TLS, cert-role authorization and key escrow are deployable end to end.
//
// This is MINIMAL provisioning for dev and small fleets, NOT a full PKI: no
// revocation/CRL/OCSP, no rotation automation, no intermediate CAs, no HSM. The
// CA private key and the escrow private key are the trust roots — whoever holds
// the CA key can mint any cert (including an operator cert, which under D58 grants
// /view), and whoever holds the escrow private key can read every escrowed file.
// Their custody is the whole scheme's security (D16); a real deployment fronts
// issuance with a proper CA / vault.
package provision

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
)

// Roles a leaf certificate may carry (must match controlplane's D58 gate — a
// drift-guard test asserts the equality).
const (
	RoleAgent    = "agent"
	RoleOperator = "operator"
	// RoleClient marks a Zero-Trust CLIENT certificate (D86) — a human or workload
	// authenticating to the access gateway. Distinct from agent/operator so a client
	// cert can never be replayed as an agent onboarding or an operator investigation
	// login at the D58 role gate. Issued via IssueClientCert, never IssueCert.
	RoleClient = "client"
)

// CertValidity bounds an issued certificate's lifetime. There is no revocation
// (the minimal-PKI limit), so a leaked cert is valid until it expires; keep it
// short-ish and re-issue to rotate.
const CertValidity = 90 * 24 * time.Hour

// clock is fixed for determinism only in tests; production uses time.Now.
var clock = time.Now

// InitCA generates an Ed25519 self-signed CA and returns its cert and private key
// as PEM. The key PEM is the trust root — guard it (D16).
func InitCA() (caCertPEM, caKeyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: CA keygen: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	now := clock()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "OpenShield provisioning CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: CA cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: CA key: %w", err)
	}
	return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
}

// IssueClientCert issues a Zero-Trust CLIENT certificate (D86), signed by the CA —
// a DISTINCT path from IssueCert (which stays agent/operator only, unchanged). The
// leaf carries CommonName = the identity (e.g. a user or workload id), OU =
// [RoleClient] (the marker, so it is never mistaken for an agent/operator cert at the
// D58 gate), and Organization = [group] (the authorization class the gateway policy
// authorizes on). clientAuth only — a client cert is not a server. The CN is the raw
// identity; the identity producer pseudonymises it at the boundary (D23), so it never
// enters the pipeline.
func IssueClientCert(caCertPEM, caKeyPEM []byte, identity, group string) (certPEM, keyPEM []byte, err error) {
	if identity == "" || group == "" {
		return nil, nil, fmt.Errorf("provision: client cert needs a non-empty identity and group")
	}
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: client leaf keygen: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	now := clock()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         identity,
			OrganizationalUnit: []string{RoleClient},
			Organization:       []string{group},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(CertValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: client leaf cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: client leaf key: %w", err)
	}
	return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
}

// InterceptionCA generates an Ed25519 self-signed CA for TLS INTERCEPTION and
// returns its cert and private key as PEM. It is DELIBERATELY SEPARATE from the
// fleet mTLS CA (InitCA): an interception CA can sign a trusted certificate for
// ANY host, so whoever holds it can impersonate the whole internet to every
// endpoint that trusts it — a far larger blast radius than fleet identity, which
// only authorises agents and operators. Fusing the two (signing MITM leaves with
// the fleet CA) would give the fleet CA that power. The CN differs so the two are
// distinguishable in a trust store; the key PEM is the trust root whose custody IS
// interception's security (D16). Deploy it as a trusted root ONLY where
// interception is authorised.
func InterceptionCA() (caCertPEM, caKeyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: interception CA keygen: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	now := clock()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "OpenShield Interception CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: interception CA cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: interception CA key: %w", err)
	}
	return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
}

// IssueCert issues an Ed25519 leaf certificate signed by the CA, carrying the
// role in the Subject Organizational Unit (D58), serverAuth+clientAuth usage, and
// the given SANs (host names and/or IPs). An unknown role is rejected — the
// enforcer never issues a cert with a role the gate will not recognise.
func IssueCert(caCertPEM, caKeyPEM []byte, cn, role string, sans []string) (certPEM, keyPEM []byte, err error) {
	if role != RoleAgent && role != RoleOperator {
		return nil, nil, fmt.Errorf("provision: unknown role %q (want %q or %q)", role, RoleAgent, RoleOperator)
	}
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: leaf keygen: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	dns, ips := splitSANs(sans)
	now := clock()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: []string{role}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(CertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: leaf cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: leaf key: %w", err)
	}
	return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
}

// EscrowKeypair generates a Curve25519 escrow keypair. The public key is
// provisioned to endpoints (loaded by encryptlocal.NewEscrow); the private key
// belongs off the endpoint (used by encryptlocal.DecryptEscrow for recovery).
func EscrowKeypair() (pub, priv []byte, err error) {
	return encryptlocal.GenerateEscrowKeypair()
}

// WitnessKeypair generates an Ed25519 anchoring-witness keypair (T-019). The
// private key runs the witness (openshield-anchor) in a trust domain the ledger
// operator does not control; the public key goes to verifiers. Raw key bytes.
func WitnessKeypair() (pub, priv []byte, err error) {
	w, err := core.NewWitness()
	if err != nil {
		return nil, nil, fmt.Errorf("provision: witness keygen: %w", err)
	}
	return append([]byte(nil), w.PublicKey()...), append([]byte(nil), w.PrivateKey()...), nil
}

func parseCA(caCertPEM, caKeyPEM []byte) (*x509.Certificate, ed25519.PrivateKey, error) {
	cb, _ := pem.Decode(caCertPEM)
	if cb == nil {
		return nil, nil, fmt.Errorf("provision: CA cert PEM invalid")
	}
	caCert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: parsing CA cert: %w", err)
	}
	kb, _ := pem.Decode(caKeyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("provision: CA key PEM invalid")
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("provision: parsing CA key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("provision: CA key is not Ed25519")
	}
	return caCert, edKey, nil
}

func splitSANs(sans []string) (dns []string, ips []net.IP) {
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, s)
		}
	}
	return dns, ips
}

func randSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("provision: serial: %w", err)
	}
	return n, nil
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
