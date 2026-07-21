// Package tlsconf loads mutual-TLS material once and hands out server and client
// *tls.Config for the agent-facing channels (enrollment HTTP + NATS telemetry).
//
// It is a channel-security layer BENEATH Ed25519 message signing (D50), which is
// unchanged: TLS authenticates the PEER and hides the wire; the signature still
// proves per-message attribution and the forward-secure ledger remains the
// evidence. The two layers are independent and both enforced.
//
// At-rest protection of the private key is filesystem permissions + the running
// user, the same bar as the signer key — host root defeats it (D16). This raises
// the on-path bar; it does not defend a compromised host.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Env var names. All three must be set to enable TLS, or none (disabled).
const (
	EnvCA   = "OPENSHIELD_TLS_CA"
	EnvCert = "OPENSHIELD_TLS_CERT"
	EnvKey  = "OPENSHIELD_TLS_KEY"
)

// Config holds parsed mutual-TLS material: the CA to verify the PEER against and
// this end's own certificate.
type Config struct {
	caPool *x509.CertPool
	cert   tls.Certificate
}

// Load parses a CA bundle and this end's cert/key pair. A read or parse failure
// is returned — a misconfiguration must fail loudly, never silently disable TLS.
func Load(caPath, certPath, keyPath string) (*Config, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: reading CA %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("tlsconf: CA %s contained no usable certificates", caPath)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: loading cert/key: %w", err)
	}
	return &Config{caPool: pool, cert: cert}, nil
}

// LoadFromEnv loads TLS material from the OPENSHIELD_TLS_* env vars. It returns
// (nil, nil) when NONE are set — TLS is off by default, the dev loop stays
// plaintext. It returns an error when only SOME are set (a partial, ambiguous
// configuration must not silently fall back to plaintext) or when the material
// cannot be loaded.
func LoadFromEnv() (*Config, error) {
	ca, cert, key := os.Getenv(EnvCA), os.Getenv(EnvCert), os.Getenv(EnvKey)
	set := 0
	for _, v := range []string{ca, cert, key} {
		if v != "" {
			set++
		}
	}
	switch set {
	case 0:
		return nil, nil // disabled — plaintext
	case 3:
		return Load(ca, cert, key)
	default:
		return nil, fmt.Errorf("tlsconf: partial TLS configuration — set all of %s/%s/%s or none",
			EnvCA, EnvCert, EnvKey)
	}
}

// ServerConfig demands and verifies a client certificate (mutual TLS): an agent
// without a CA-issued cert is refused at the handshake, before any token is seen.
func (c *Config) ServerConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{c.cert},
		ClientCAs:    c.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// ClientConfig presents this end's certificate and verifies the server against
// the CA.
func (c *Config) ClientConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{c.cert},
		RootCAs:      c.caPool,
		MinVersion:   tls.VersionTLS13,
	}
}
