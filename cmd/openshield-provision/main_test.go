package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lucianoengel/openshield/internal/provision"
)

// THE INVARIANT THIS FILE EXISTS FOR.
//
// Every artifact this tool mints is either a public credential or a trust root, and the difference is
// carried by nothing but the mode argument at the call site. A CA key written 0644 is a fleet compromise
// that nothing else in the system would notice: the certificates it mints stay valid, every test still
// passes, and the only symptom is that any local account can mint an agent or operator identity.
//
// So the modes are asserted per file, and the private ones are asserted by GROUP/OTHER BITS rather than by
// an exact 0600 — os.WriteFile applies the umask, so an exact comparison would be testing the developer's
// shell rather than the code.
func TestPrivateArtifactsAreNotReadableByAnyoneElse(t *testing.T) {
	for _, tc := range []struct {
		cmd     string
		args    func(dir string) []string
		private []string
		public  []string
	}{
		{
			cmd:     "ca-init",
			args:    func(d string) []string { return []string{"ca-init", "--out", d} },
			private: []string{"ca-key.pem"},
			public:  []string{"ca.pem"},
		},
		{
			cmd:     "escrow-keygen",
			args:    func(d string) []string { return []string{"escrow-keygen", "--out", d} },
			private: []string{"escrow-priv"},
			public:  []string{"escrow-pub"},
		},
		{
			cmd:     "witness-keygen",
			args:    func(d string) []string { return []string{"witness-keygen", "--out", d} },
			private: []string{"witness-priv"},
			public:  []string{"witness-pub"},
		},
		{
			cmd:     "risk-keygen",
			args:    func(d string) []string { return []string{"risk-keygen", "--out", d} },
			private: []string{"risk-priv"},
			public:  []string{"risk-pub"},
		},
		{
			cmd:     "posture-keygen",
			args:    func(d string) []string { return []string{"posture-keygen", "--out", d} },
			private: []string{"posture-priv"},
			public:  []string{"posture-pub"},
		},
		{
			cmd:     "intercept-ca",
			args:    func(d string) []string { return []string{"intercept-ca", "--out", d} },
			private: []string{"intercept-ca-key.pem"},
			public:  []string{"intercept-ca.pem"},
		},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			dir := t.TempDir()
			if code := run(tc.args(dir)); code != 0 {
				t.Fatalf("%s exited %d", tc.cmd, code)
			}
			for _, name := range tc.private {
				fi, err := os.Stat(filepath.Join(dir, name))
				if err != nil {
					t.Fatalf("%s was not written: %v", name, err)
				}
				if perm := fi.Mode().Perm(); perm&0o077 != 0 {
					t.Errorf("%s is mode %04o — a private key readable by group or other", name, perm)
				}
			}
			for _, name := range tc.public {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Fatalf("%s was not written: %v", name, err)
				}
			}
		})
	}
}

// A minted certificate has to actually chain to the CA that signed it and carry its role where the
// verifiers look for it. Writing two well-formed PEM files is not the same as issuing a usable identity.
func TestAnIssuedCertificateChainsToTheCAAndCarriesItsRole(t *testing.T) {
	ca := t.TempDir()
	if code := run([]string{"ca-init", "--out", ca}); code != 0 {
		t.Fatalf("ca-init exited %d", code)
	}
	leaf := t.TempDir()
	if code := run([]string{"cert", "--ca", ca, "--role", "operator", "--cn", "alice", "--san", "alice.example", "--out", leaf}); code != 0 {
		t.Fatalf("cert exited %d", code)
	}

	caCert := parseCert(t, filepath.Join(ca, "ca.pem"))
	leafCert := parseCert(t, filepath.Join(leaf, "cert.pem"))

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("the issued certificate does not chain to the CA that signed it: %v", err)
	}
	if leafCert.Subject.CommonName != "alice" {
		t.Errorf("CN = %q, want alice", leafCert.Subject.CommonName)
	}
	if !contains(leafCert.Subject.OrganizationalUnit, "operator") {
		t.Errorf("role is not in Subject OU: %v", leafCert.Subject.OrganizationalUnit)
	}
	if !contains(leafCert.DNSNames, "alice.example") {
		t.Errorf("--san did not reach the certificate: %v", leafCert.DNSNames)
	}
	if fi, err := os.Stat(filepath.Join(leaf, "key.pem")); err != nil {
		t.Fatal(err)
	} else if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("key.pem is mode %04o — readable by group or other", perm)
	}
}

// D86: the access proxy refuses a client certificate with no authorization group, so issuing one would
// produce a credential that cannot be used and whose failure surfaces at the proxy, not here.
//
// This test asserts the PROPERTY (no groupless client certificate is ever written), not one particular
// guard, and the distinction is not academic: the check exists twice, in this command and again in
// provision.IssueClientCert. Removing either one alone leaves the property intact and this test green —
// which is what defence in depth is supposed to look like. Removing BOTH does fail it, so the test is not
// merely passing on the library's behalf.
func TestAClientCertificateWithoutAGroupIsRefused(t *testing.T) {
	ca := t.TempDir()
	if code := run([]string{"ca-init", "--out", ca}); code != 0 {
		t.Fatalf("ca-init exited %d", code)
	}
	out := t.TempDir()
	if code := run([]string{"cert", "--ca", ca, "--role", provision.RoleClient, "--cn", "bob", "--out", out}); code == 0 {
		t.Fatal("a client certificate with no --group was issued anyway")
	}
	if _, err := os.Stat(filepath.Join(out, "cert.pem")); err == nil {
		t.Fatal("a certificate file was written despite the refusal")
	}

	if code := run([]string{"cert", "--ca", ca, "--role", provision.RoleClient, "--cn", "bob", "--group", "engineering", "--out", out}); code != 0 {
		t.Fatalf("a client certificate WITH a group was refused, exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(out, "cert.pem")); err != nil {
		t.Fatalf("no certificate written: %v", err)
	}
}

func TestUnusableInvocationsExitNonZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, 2},
		{"unknown command", []string{"mint-me-a-pony"}, 2},
		{"ca-init without --out", []string{"ca-init"}, 1},
		{"escrow-keygen without --out", []string{"escrow-keygen"}, 1},
		{"witness-keygen without --out", []string{"witness-keygen"}, 1},
		{"risk-keygen without --out", []string{"risk-keygen"}, 1},
		{"posture-keygen without --out", []string{"posture-keygen"}, 1},
		{"intercept-ca without --out", []string{"intercept-ca"}, 1},
		{"cert with no flags", []string{"cert"}, 1},
		{"posture-enroll with no flags", []string{"posture-enroll"}, 2},
		{"cert against a missing CA", []string{"cert", "--ca", "/nonexistent", "--role", "agent", "--cn", "x", "--out", t.TempDir()}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.args); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}

func TestFlagParsing(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want map[string][]string
	}{
		{"simple pair", []string{"--out", "dir"}, map[string][]string{"out": {"dir"}}},
		{"repeated flag keeps every value", []string{"--san", "a", "--san", "b"}, map[string][]string{"san": {"a", "b"}}},
		{"a valueless flag records presence", []string{"--block"}, map[string][]string{"block": {""}}},
		{"a valueless flag before another", []string{"--block", "--out", "d"}, map[string][]string{"block": {""}, "out": {"d"}}},
		{"bare words are ignored", []string{"junk", "--out", "d"}, map[string][]string{"out": {"d"}}},
		{"nothing", nil, map[string][]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := flags(tc.args); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("flags(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}

	// `has` treats presence as the value, which is what makes `--block` mean block.
	if !has(flags([]string{"--block"}), "block") {
		t.Error("a flag that was given reads as absent")
	}
	if has(flags([]string{"--out", "d"}), "block") {
		t.Error("a flag that was not given reads as present")
	}
	if got := one(flags(nil), "out"); got != "" {
		t.Errorf("one() on a missing flag = %q, want empty", got)
	}
}

func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(blob)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return c
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
