package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// "EVERY CONFIGURATION PROBLEM IS FATAL. A ZTNA client that started without a device certificate would
// forward traffic unauthenticated while looking like protection — worse than not running, because the
// application keeps working and nobody learns the identity was never presented."
//
// That is the contract of this binary, and it is asserted on the MESSAGE rather than the exit code alone:
// every one of these paths returns 1, so an exit-code test would pass no matter which check fired, or
// whether the right one fired at all.

func writePEM(t *testing.T, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "device"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	caPath = filepath.Join(dir, "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for path, blob := range map[string][]byte{
		certPath: certPEM,
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		caPath:   certPEM,
	} {
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath, caPath
}

// runCapturing swaps os.Stderr for a pipe around one run() call.
func runCapturing(t *testing.T) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()

	code := run()

	os.Stderr = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return code, out
}

// setAll configures a complete, valid environment; individual tests then break one thing.
func setAll(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cert, key, ca := writePEM(t, dir)
	t.Setenv("OPENSHIELD_ZTNA_BROKER", "https://broker.internal")
	t.Setenv("OPENSHIELD_ZTNA_CERT", cert)
	t.Setenv("OPENSHIELD_ZTNA_KEY", key)
	t.Setenv("OPENSHIELD_ZTNA_CA", ca)
	// A NON-loopback listen address, so run() reaches the end of its configuration work and then returns
	// on the library's loopback refusal instead of serving forever. That makes the whole happy path
	// testable without binding anything or blocking.
	t.Setenv("OPENSHIELD_ZTNA_LISTEN", "0.0.0.0:0")
}

func TestEveryMissingSettingIsFatalAndNamed(t *testing.T) {
	for _, missing := range []string{
		"OPENSHIELD_ZTNA_BROKER",
		"OPENSHIELD_ZTNA_CERT",
		"OPENSHIELD_ZTNA_KEY",
		"OPENSHIELD_ZTNA_CA",
	} {
		t.Run(missing, func(t *testing.T) {
			setAll(t)
			t.Setenv(missing, "")

			code, stderr := runCapturing(t)
			if code != 1 {
				t.Fatalf("run without %s returned %d, want 1", missing, code)
			}
			if !strings.Contains(stderr, missing) {
				t.Fatalf("the refusal does not name %s, so an operator cannot tell WHICH setting is "+
					"missing:\n%s", missing, stderr)
			}
			// It must not have gone on to announce itself as running.
			if strings.Contains(stderr, "brokering to") {
				t.Fatalf("it announced itself as brokering despite %s being unset:\n%s", missing, stderr)
			}
		})
	}
}

func TestAnUnusableBrokerURLIsRefused(t *testing.T) {
	for _, broker := range []string{"://", "not a url at all", "/just/a/path", "https://"} {
		t.Run(broker, func(t *testing.T) {
			setAll(t)
			t.Setenv("OPENSHIELD_ZTNA_BROKER", broker)

			code, stderr := runCapturing(t)
			if code != 1 {
				t.Fatalf("broker %q returned %d, want 1", broker, code)
			}
			if !strings.Contains(stderr, "OPENSHIELD_ZTNA_BROKER") {
				t.Fatalf("the refusal does not name the broker setting:\n%s", stderr)
			}
		})
	}
}

// "NOT a warning. An empty pool would make the client trust nothing and fail every request with a
// verification error, which reads as a broker problem rather than a configuration one."
func TestACAFileWithNoCertificatesIsFatalRatherThanAWarning(t *testing.T) {
	setAll(t)
	empty := filepath.Join(t.TempDir(), "empty-ca.pem")
	if err := os.WriteFile(empty, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHIELD_ZTNA_CA", empty)

	code, stderr := runCapturing(t)
	if code != 1 {
		t.Fatalf("a CA file with no certificates returned %d, want 1", code)
	}
	if !strings.Contains(stderr, "no certificates") {
		t.Fatalf("the refusal does not say the CA file held no certificates, so it reads as a broker "+
			"problem:\n%s", stderr)
	}
	if strings.Contains(stderr, "brokering to") {
		t.Fatalf("it started anyway, trusting nothing:\n%s", stderr)
	}
}

func TestAnUnloadableDeviceIdentityIsRefused(t *testing.T) {
	setAll(t)
	bad := filepath.Join(t.TempDir(), "bad-cert.pem")
	if err := os.WriteFile(bad, []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHIELD_ZTNA_CERT", bad)

	code, stderr := runCapturing(t)
	if code != 1 {
		t.Fatalf("an unloadable identity returned %d, want 1", code)
	}
	if !strings.Contains(stderr, "device identity") {
		t.Fatalf("the refusal does not name the device identity:\n%s", stderr)
	}
}

// A fully valid configuration must get PAST every check and reach the server. It is proved here by the
// library's loopback refusal firing, which can only happen after the identity loaded, the CA parsed and
// the client was constructed.
//
// The startup notice is asserted at the same time. It exists because "a README is read once; an
// application that later reaches the network directly is not announced by anything" — so the process has
// to state its limits every time it starts, and the most important of those is that it does NOT prevent
// bypass. A ZTNA client silently believed to be a network jail is a worse position than not running one.
func TestAValidConfigurationReachesTheServerAndStatesItsLimits(t *testing.T) {
	setAll(t)

	code, stderr := runCapturing(t)
	if code != 1 {
		t.Fatalf("run returned %d; with a non-loopback listen address the library must refuse", code)
	}
	if !strings.Contains(stderr, "brokering to") {
		t.Fatalf("configuration did not complete — it failed before constructing the client:\n%s", stderr)
	}
	if !strings.Contains(stderr, "loopback") {
		t.Fatalf("the non-loopback bind was not refused; the client would relay this device's identity "+
			"for anyone who can route to it:\n%s", stderr)
	}
	for _, claim := range []string{
		"DOES NOT PREVENT BYPASS",
		"not a network jail",
		"not an enrolment tool",
	} {
		if !strings.Contains(stderr, claim) {
			t.Errorf("the startup notice no longer states %q; these limits are announced every start "+
				"precisely because a README is read once:\n%s", claim, stderr)
		}
	}
}

// The default listen address must be LOOPBACK: a default of 0.0.0.0 would make every unconfigured
// deployment a relay for this device's identity.
//
// Testing it is awkward for a reason worth writing down. The default is a WORKING address, so with it in
// place run() binds and serves forever — my first version of this test hung the package until the
// timeout killed it. The address is therefore occupied first, so ListenAndServe fails immediately and
// run() returns, having already announced the address it chose.
func TestTheDefaultListenAddressIsLoopback(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:3128")
	if err != nil {
		t.Skipf("cannot occupy the default address to test it without serving: %v", err)
	}
	defer occupied.Close()

	setAll(t)
	t.Setenv("OPENSHIELD_ZTNA_LISTEN", "")

	code, stderr := runCapturing(t)
	if code != 1 {
		t.Fatalf("run returned %d with its default address already taken, want 1", code)
	}
	if !strings.Contains(stderr, "127.0.0.1:3128") {
		t.Fatalf("the default listen address is not the documented loopback one:\n%s", stderr)
	}
	// It must have been REFUSED by the OS (address in use), not by the loopback guard — proving the
	// default really is a loopback address the guard accepts.
	if strings.Contains(stderr, "loopback") {
		t.Fatalf("the DEFAULT address was rejected by the loopback guard, so the default is not "+
			"loopback:\n%s", stderr)
	}
}
