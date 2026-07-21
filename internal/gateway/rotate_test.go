package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"testing"

	"github.com/lucianoengel/openshield/internal/gateway"
)

func caPool(t *testing.T, certPEM []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	cb, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	p.AddCert(c)
	return p
}

func leafFor(t *testing.T, m *gateway.CertMinter, host string) *x509.Certificate {
	t.Helper()
	tc, err := m.For(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// After rotating to a new CA, a re-minted leaf chains to the NEW CA and no longer
// verifies against the OLD one — the cache is flushed and the new CA is in use.
func TestRotateSwapsCAAndFlushesCache(t *testing.T) {
	cert1, key1 := interceptionCA(t)
	cert2, key2 := interceptionCA(t)
	m, err := gateway.NewCertMinter(cert1, key1)
	if err != nil {
		t.Fatal(err)
	}

	pool1, pool2 := caPool(t, cert1), caPool(t, cert2)

	// Under CA1, the leaf verifies against CA1, not CA2.
	l1 := leafFor(t, m, "upload.example.com")
	if _, err := l1.Verify(x509.VerifyOptions{DNSName: "upload.example.com", Roots: pool1}); err != nil {
		t.Fatalf("pre-rotation leaf should verify against CA1: %v", err)
	}

	if err := m.Rotate(cert2, key2); err != nil {
		t.Fatal(err)
	}

	// The SAME host now mints a leaf chaining to CA2 (cache was flushed), and it
	// does NOT verify against CA1.
	l2 := leafFor(t, m, "upload.example.com")
	if _, err := l2.Verify(x509.VerifyOptions{DNSName: "upload.example.com", Roots: pool2}); err != nil {
		t.Errorf("post-rotation leaf should verify against CA2: %v", err)
	}
	if _, err := l2.Verify(x509.VerifyOptions{DNSName: "upload.example.com", Roots: pool1}); err == nil {
		t.Error("post-rotation leaf still verifies against the rotated-away CA1 — cache not flushed / CA not swapped")
	}
}

// A rotation with invalid PEM fails and leaves the minter working with the old CA.
func TestRotateFailSafeOnInvalidCA(t *testing.T) {
	cert1, key1 := interceptionCA(t)
	m, _ := gateway.NewCertMinter(cert1, key1)

	if err := m.Rotate([]byte("not a pem"), []byte("nope")); err == nil {
		t.Fatal("Rotate accepted an invalid CA — a bad rotation must fail")
	}
	// The minter still works with CA1.
	l := leafFor(t, m, "still.example.com")
	if _, err := l.Verify(x509.VerifyOptions{DNSName: "still.example.com", Roots: caPool(t, cert1)}); err != nil {
		t.Errorf("after a failed rotation the minter should still mint under CA1: %v", err)
	}
}

// Rotate concurrent with For is race-safe (run under -race).
func TestRotateRaceSafe(t *testing.T) {
	cert1, key1 := interceptionCA(t)
	cert2, key2 := interceptionCA(t)
	m, _ := gateway.NewCertMinter(cert1, key1)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.For(&tls.ClientHelloInfo{ServerName: "h.example.com"})
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = m.Rotate(cert2, key2)
	}()
	wg.Wait()
}
