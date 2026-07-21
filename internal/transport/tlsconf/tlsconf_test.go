package tlsconf_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/transport/tlsconf"
)

// --- tiny in-test CA: enough to issue leaf certs for a real handshake ---

type ca struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	der  []byte
}

func newCA(t *testing.T, name string) *ca {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &ca{cert: cert, key: priv, der: der}
}

// issue writes a CA-signed leaf cert + key to dir and returns their paths, plus
// the CA bundle path.
func (c *ca) issue(t *testing.T, dir, name string) (caPath, certPath, keyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)

	caPath = filepath.Join(dir, name+"-ca.pem")
	certPath = filepath.Join(dir, name+"-cert.pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	writePEM(t, caPath, "CERTIFICATE", c.der)
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	return caPath, certPath, keyPath
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// 3.1 — the loader's configs enforce MUTUAL TLS: a client with a CA-issued cert
// completes the handshake, and a client from a DIFFERENT CA is refused.
func TestMutualTLSEnforced(t *testing.T) {
	dir := t.TempDir()
	goodCA := newCA(t, "good-ca")
	caPath, srvCert, srvKey := goodCA.issue(t, dir, "server")
	_, cliCert, cliKey := goodCA.issue(t, dir, "client")

	srvConf, err := tlsconf.Load(caPath, srvCert, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the server config demands and verifies a client cert.
	if srvConf.ServerConfig().ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("server config does not require+verify a client certificate")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvConf.ServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Force the handshake, then close.
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()

	dial := func(caP, certP, keyP string) error {
		cfg, err := tlsconf.Load(caP, certP, keyP)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		d := &tls.Dialer{Config: cfg.ClientConfig()}
		conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if conn != nil {
			conn.Close()
		}
		return err
	}

	// A client with a cert from the SAME CA succeeds.
	if err := dial(caPath, cliCert, cliKey); err != nil {
		t.Fatalf("valid mutual-TLS client was refused: %v", err)
	}
	// A client whose cert is from a DIFFERENT CA is refused at the handshake.
	otherCA := newCA(t, "rogue-ca")
	oCaPath, oCert, oKey := otherCA.issue(t, dir, "rogue-client")
	if err := dial(oCaPath, oCert, oKey); err == nil {
		t.Fatal("a client from a different CA completed the handshake — mutual TLS not enforced")
	}
}

// 3.3 — LoadFromEnv is disabled by default (unset → nil, plaintext) and fails
// LOUDLY on a partial configuration rather than silently serving plaintext.
func TestLoadFromEnvDefaultAndPartial(t *testing.T) {
	// Unset → nil, no error (plaintext dev loop).
	for _, k := range []string{tlsconf.EnvCA, tlsconf.EnvCert, tlsconf.EnvKey} {
		t.Setenv(k, "")
	}
	cfg, err := tlsconf.LoadFromEnv()
	if err != nil || cfg != nil {
		t.Fatalf("unset env: got (%v, %v), want (nil, nil) — TLS must be off by default", cfg, err)
	}

	// Partial (only CA set) → hard error, never a silent plaintext fallback.
	t.Setenv(tlsconf.EnvCA, "/nonexistent/ca.pem")
	cfg, err = tlsconf.LoadFromEnv()
	if err == nil || cfg != nil {
		t.Fatalf("partial env: got (%v, %v), want (nil, error) — a partial config must fail loud", cfg, err)
	}
}
