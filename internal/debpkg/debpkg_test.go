package debpkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/release"
)

// signedRelease builds a small but REAL signed release directory: artifacts, manifest, signature. Real
// rather than faked, because the property under test is that packaging is gated on verification, and a
// stubbed verifier would be the test agreeing with itself.
func signedRelease(t *testing.T) (dir string, pub ed25519.PublicKey) {
	t.Helper()
	dir = t.TempDir()
	for _, name := range []string{
		"openshield-engine_linux_amd64",
		"openshield-gateway_linux_amd64",
		"openshieldctl_linux_arm64", // another arch, to prove selection is real
		"openshieldctl_darwin_amd64",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("ELF-ish "+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	platform := func(name string) string {
		switch {
		case strings.HasSuffix(name, "_linux_amd64"):
			return "linux/amd64"
		case strings.HasSuffix(name, "_linux_arm64"):
			return "linux/arm64"
		default:
			return "darwin/amd64"
		}
	}
	m, err := release.Build(dir, "1.2.3", "abc123", "go1.26", platform)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := release.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, release.ManifestName), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, release.SignatureName), sig, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, pubKey
}

func spec(t *testing.T) Spec {
	dir, pub := signedRelease(t)
	return Spec{
		Name: "openshield", Version: "1.2.3", Arch: "amd64",
		Maintainer: "OpenShield <security@example.invalid>",
		Dir:        dir, PublicKey: pub,
	}
}

// tarEntries lists the paths inside a gzipped tar member.
func tarEntries(t *testing.T, gz []byte) map[string]int64 {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		out[h.Name] = h.Mode
	}
	return out
}

// members splits a built .deb into its ar members.
func members(t *testing.T, deb []byte) map[string][]byte {
	t.Helper()
	if !bytes.HasPrefix(deb, []byte("!<arch>\n")) {
		t.Fatal("not an ar archive")
	}
	out := map[string][]byte{}
	p := deb[8:]
	for len(p) >= 60 {
		name := strings.TrimSpace(string(p[0:16]))
		var size int64
		if _, err := fmtSscan(strings.TrimSpace(string(p[48:58])), &size); err != nil {
			t.Fatalf("bad member size for %q", name)
		}
		if string(p[58:60]) != "`\n" {
			t.Fatalf("member %q has no header magic — every later offset is wrong", name)
		}
		body := p[60 : 60+size]
		out[name] = body
		adv := 60 + size
		if size%2 == 1 {
			adv++
		}
		p = p[adv:]
	}
	return out
}

func fmtSscan(s string, v *int64) (int, error) {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errNotNumber
		}
		n = n*10 + int64(c-'0')
	}
	*v = n
	return 1, nil
}

var errNotNumber = &numErr{}

type numErr struct{}

func (*numErr) Error() string { return "not a number" }

// AN UNVERIFIABLE RELEASE IS NOT PACKAGED. This is the reason the package exists.
//
// deploy/install.sh runs `go build` on the target host, so an operator following the documented path runs
// binaries nobody signed. Packaging would be no better — worse, in fact — if it accepted any directory:
// `dpkg -i` asks no questions, so a .deb launders whatever it contains into a format the operator's
// tooling trusts by default.
//
// Mutation, stated accurately because the obvious one does NOT kill: deleting the explicit verify call in
// Build leaves this test passing, since artifact SELECTION also goes through the verifier and there is no
// path to the file list that skips it. That is defence in depth rather than a gap, but a claim that the
// explicit check is what this test pins would have been false. The mutation that DOES kill is disabling
// the digest comparison inside release.Verify — confirmed by doing it.
func TestATamperedReleaseIsNotPackaged(t *testing.T) {
	s := spec(t)
	// One artifact edited after signing — the supply-chain attack this whole pipeline is aimed at.
	victim := filepath.Join(s.Dir, "openshield-engine_linux_amd64")
	if err := os.WriteFile(victim, []byte("backdoored"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(s); err == nil {
		t.Fatal("a release whose binary was modified after signing was packaged. The .deb would install " +
			"an unattested binary as root on every endpoint, and dpkg would report success")
	}
}

// AND NEITHER IS ONE NOBODY OFFERED A KEY FOR.
//
// A missing key must be an ERROR, never a skipped check: "we could not verify" and "it verified" are
// opposite answers, and defaulting to the second is how a gate becomes decoration.
func TestPackagingWithoutAKeyIsRefused(t *testing.T) {
	s := spec(t)
	s.PublicKey = nil
	if _, err := Build(s); err == nil {
		t.Fatal("a package was built with no verification key at all — the integrity gate is optional, " +
			"which means it is not a gate")
	}
}

// THE HAPPY PATH: a verified release becomes a well-formed package.
func TestAVerifiedReleaseBecomesAWellFormedPackage(t *testing.T) {
	pkg, err := Build(spec(t))
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Filename != "openshield_1.2.3_amd64.deb" {
		t.Errorf("filename %q does not follow the Debian convention", pkg.Filename)
	}
	m := members(t, pkg.Bytes)
	if string(m["debian-binary"]) != "2.0\n" {
		t.Errorf("debian-binary is %q", m["debian-binary"])
	}
	for _, want := range []string{"debian-binary", "control.tar.gz", "data.tar.gz"} {
		if _, ok := m[want]; !ok {
			t.Fatalf("member %s is missing — dpkg reads all three in order", want)
		}
	}
	ctrl := tarEntries(t, m["control.tar.gz"])
	if _, ok := ctrl["./control"]; !ok {
		t.Error("no control file")
	}
	if mode := ctrl["./postinst"]; mode&0o111 == 0 {
		t.Errorf("postinst is not executable (mode %o) — dpkg will not run it, so the service users are "+
			"never created and every unit fails to start", mode)
	}
}

// ONLY THIS ARCHITECTURE'S LINUX BINARIES GO IN.
//
// The selection comes from the manifest's per-artifact platform rather than a hardcoded list, so it
// cannot drift as commands are added. An amd64 package containing an arm64 or darwin binary would install
// something that cannot execute, and the failure would appear at first run rather than at build.
func TestOnlyTheTargetPlatformsBinariesArePackaged(t *testing.T) {
	pkg, err := Build(spec(t))
	if err != nil {
		t.Fatal(err)
	}
	data := tarEntries(t, members(t, pkg.Bytes)["data.tar.gz"])
	if _, ok := data["./usr/bin/openshield-engine"]; !ok {
		t.Fatalf("the linux/amd64 engine is not in the package: %v", keys(data))
	}
	for name := range data {
		if strings.Contains(name, "arm64") || strings.Contains(name, "darwin") {
			t.Errorf("%s was packaged into an amd64 .deb — it cannot execute on the target", name)
		}
	}
}

// THE INSTALLED NAME IS THE COMMAND'S NAME.
//
// Release artifacts carry a platform suffix so they can share one directory. Installing
// `openshield-engine-linux-amd64` into /usr/bin would mean every unit file, every document and every
// operator's muscle memory refers to a binary that is not there.
func TestTheInstalledBinaryHasTheNameOperatorsType(t *testing.T) {
	pkg, err := Build(spec(t))
	if err != nil {
		t.Fatal(err)
	}
	data := tarEntries(t, members(t, pkg.Bytes)["data.tar.gz"])
	for name := range data {
		if strings.Contains(name, "_linux_amd64") {
			t.Errorf("%s kept its release platform suffix; the systemd units reference the bare name", name)
		}
	}
	if mode := data["./usr/bin/openshield-engine"]; mode&0o111 == 0 {
		t.Errorf("the installed binary is not executable (mode %o)", mode)
	}
}

// THE PACKAGE INSTALLS UNDER /usr, NOT /usr/local.
//
// /usr/local belongs to the local administrator; a package manager writing there collides with whatever
// the operator put in it, and dpkg cannot then own the files it placed.
func TestThePackageDoesNotWriteIntoUsrLocal(t *testing.T) {
	pkg, err := Build(spec(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range pkg.Files {
		if strings.HasPrefix(f, "/usr/local/") {
			t.Errorf("%s is under /usr/local, which belongs to the administrator rather than to dpkg", f)
		}
	}
}

// NOTHING IS ENABLED BY INSTALLING.
//
// fanotify on an unconfigured host is the operator's call — the same choice install.sh makes. A security
// package that starts enforcing at `dpkg -i` is one that breaks a machine during a routine upgrade.
func TestInstallingDoesNotStartEnforcing(t *testing.T) {
	// Only what the script RUNS counts. It is allowed — and expected — to PRINT the enable command as
	// advice; a security package that installs silently and does nothing looks exactly like one that is
	// working. The distinction matters enough that this test strips the echoes rather than banning the
	// words, which is what its first version did.
	var executed []string
	for _, line := range strings.Split(postinst(), "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "echo ") && !strings.HasPrefix(t, "#") {
			executed = append(executed, t)
		}
	}
	run := strings.Join(executed, "\n")
	if strings.Contains(run, "systemctl enable") || strings.Contains(run, "systemctl start") {
		t.Fatalf("postinst RUNS an enable or start. Installing a package must not begin enforcing on a "+
			"host nobody has configured yet:\n%s", run)
	}
	post := postinst()
	if !strings.Contains(post, "daemon-reload") {
		t.Error("postinst never reloads systemd, so freshly installed units are invisible until reboot")
	}
	for _, u := range serviceUsers {
		if !strings.Contains(post, u) {
			t.Errorf("postinst does not create %s — its unit runs as that user and will fail to start", u)
		}
	}
}

// REMOVAL DOES NOT DELETE THE SERVICE USERS.
//
// The engine owns forward-secure ledger signer state on disk. Deleting its user orphans those files to a
// uid that no longer resolves, and a reinstall gets a different uid and cannot read its own state — a
// tamper-evident ledger made unreadable by an uninstall. A leftover system account is the smaller harm.
func TestRemovalLeavesTheServiceUsersAlone(t *testing.T) {
	pre := prerm()
	for _, bad := range []string{"deluser", "userdel", "delgroup", "groupdel"} {
		if strings.Contains(pre, bad) {
			t.Errorf("prerm runs %s. That orphans the engine's ledger signer state to an unresolvable "+
				"uid, and a reinstall cannot read it", bad)
		}
	}
	if !strings.Contains(pre, "systemctl stop") {
		t.Error("prerm does not stop the units, so systemd is left supervising binaries that are being " +
			"deleted underneath it")
	}
}

func keys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
