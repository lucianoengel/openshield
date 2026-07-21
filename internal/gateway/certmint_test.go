package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/provision"
)

func interceptionCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	c, k, err := provision.InterceptionCA()
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// The minter produces a leaf for an SNI that chains to the interception CA and is
// valid for that host — the property that makes the terminated TLS trusted.
func TestCertMinterMintsChainingLeaf(t *testing.T) {
	certPEM, keyPEM := interceptionCA(t)
	m, err := gateway.NewCertMinter(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := m.For(&tls.ClientHelloInfo{ServerName: "upload.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	// The leaf chains to the CA and is valid for the host.
	roots := x509.NewCertPool()
	cb, _ := pem.Decode(certPEM)
	caCert, _ := x509.ParseCertificate(cb.Bytes)
	roots.AddCert(caCert)
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leafCert.Verify(x509.VerifyOptions{DNSName: "upload.example.com", Roots: roots}); err != nil {
		t.Errorf("minted leaf does not verify against the interception CA: %v", err)
	}

	// A second call for the same host returns the cached leaf.
	leaf2, _ := m.For(&tls.ClientHelloInfo{ServerName: "upload.example.com"})
	if leaf2 != leaf {
		t.Error("minter did not cache the leaf for a repeated host")
	}
}

// An empty SNI is rejected — no host, no cert.
func TestCertMinterRejectsEmptySNI(t *testing.T) {
	certPEM, keyPEM := interceptionCA(t)
	m, _ := gateway.NewCertMinter(certPEM, keyPEM)
	if _, err := m.For(&tls.ClientHelloInfo{ServerName: ""}); err == nil {
		t.Error("empty SNI was accepted — a leaf cannot be minted for an unnamed host")
	}
}
