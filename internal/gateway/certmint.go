package gateway

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CertMinter mints leaf certificates on the fly for TLS interception: given the
// SNI hostname a client is connecting to, it returns a certificate for that host
// signed by the SEPARATE interception CA (never the fleet CA — D74/D75), so the
// terminated client TLS presents a cert the client trusts.
//
// The interception CA private key held here is a skeleton key: it can impersonate
// any host to any endpoint that trusts the CA. Its custody is the whole scheme's
// security (D16).
type CertMinter struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	caDER  []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// NewCertMinter loads the interception CA from PEM (as produced by
// provision.InterceptionCA).
func NewCertMinter(caCertPEM, caKeyPEM []byte) (*CertMinter, error) {
	cb, _ := pem.Decode(caCertPEM)
	if cb == nil {
		return nil, fmt.Errorf("certmint: CA cert PEM undecodable")
	}
	caCert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certmint: parsing CA cert: %w", err)
	}
	kb, _ := pem.Decode(caKeyPEM)
	if kb == nil {
		return nil, fmt.Errorf("certmint: CA key PEM undecodable")
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certmint: parsing CA key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("certmint: CA key is not a signer (%T)", key)
	}
	return &CertMinter{
		caCert: caCert,
		caKey:  signer,
		caDER:  cb.Bytes,
		cache:  map[string]*tls.Certificate{},
	}, nil
}

// For is a tls.Config.GetCertificate callback: it mints (and caches) a leaf for the
// SNI hostname. An empty SNI is rejected — without a host there is no cert to mint,
// and guessing one would present a wrong certificate.
func (m *CertMinter) For(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.ForHost(hello.ServerName)
}

// ForHost mints (and caches) a leaf for an explicit host — used by the interceptor
// which falls back to the CONNECT host when the client sends no SNI (an IP literal).
// An empty host is rejected.
func (m *CertMinter) ForHost(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, fmt.Errorf("certmint: no host — cannot mint a leaf for an unnamed host")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.cache[host]; ok {
		return c, nil
	}
	leaf, err := m.mint(host)
	if err != nil {
		return nil, err
	}
	m.cache[host] = leaf
	return leaf, nil
}

func (m *CertMinter) mint(host string) (*tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("certmint: leaf keygen: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certmint: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// An IP literal goes in the IP SAN (a client validating an IP does not match
	// DNSNames); a hostname goes in DNSNames.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, pub, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("certmint: leaf cert: %w", err)
	}
	return &tls.Certificate{
		// The leaf plus the CA, so a client that has the CA as a root gets a
		// complete chain even if it does not already hold the CA cert inline.
		Certificate: [][]byte{der, m.caDER},
		PrivateKey:  priv,
		Leaf:        tmpl,
	}, nil
}
