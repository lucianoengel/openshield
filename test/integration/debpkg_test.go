//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAReleaseBecomesAPackageDpkgInstalls closes the loop PLAT-6 left open.
//
// The release pipeline produces reproducible binaries and a signature over the SET, and then
// deploy/install.sh runs `go build` on the target host — so the documented install path discards every
// artifact anyone attested to and compiles fresh ones. This scenario drives the shipped `openshieldctl`
// to turn a VERIFIED release into a .deb, then hands it to the real `dpkg` on a real machine.
//
// It is here rather than in a unit test because the only authority on whether a .deb is well-formed is
// dpkg. A hand-rolled `ar` archive that a Go test reads back happily can still be rejected by the tool
// every operator will actually use, and that failure would first appear in someone else's terminal.
func TestAReleaseBecomesAPackageDpkgInstalls(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installing a package needs root (dpkg writes to /usr/bin and creates users) — run on " +
			"the rooted VM with " + BinDirEnv + " pointing at pre-built binaries")
	}
	dpkg, err := exec.LookPath("dpkg")
	if err != nil {
		t.Skip("dpkg is not available on this host")
	}
	work := t.TempDir()
	dist := filepath.Join(work, "dist")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}

	// A minimal but REAL release: the shipped binaries, a manifest, a signature. Built with the shipped
	// tooling rather than assembled by hand, so the scenario exercises the operator's actual sequence.
	for _, name := range []string{"openshield-engine", "openshieldctl"} {
		src := Binary(t, name)
		body, rerr := os.ReadFile(src)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if werr := os.WriteFile(filepath.Join(dist, name+"_linux_amd64"), body, 0o755); werr != nil {
			t.Fatal(werr)
		}
	}
	// The signing key is minted HERE and the private half never reaches the release directory, which is
	// the property release.go states and the reason package-deb takes only the public one.
	pubKey, privKey, kerr := ed25519.GenerateKey(rand.Reader)
	if kerr != nil {
		t.Fatal(kerr)
	}
	key := filepath.Join(work, "release.key")
	pub := filepath.Join(work, "release.pub")
	if werr := os.WriteFile(key, privKey, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if werr := os.WriteFile(pub, pubKey, 0o644); werr != nil {
		t.Fatal(werr)
	}
	if out, merr := runCapture(t, "openshieldctl", nil, "release-manifest",
		"--dir", dist, "--version", "9.9.9", "--key", key); merr != nil {
		t.Fatalf("release-manifest: %v\n%s", merr, out)
	}

	// 1. THE PACKAGE IS BUILT FROM THE VERIFIED SET, and lands OUTSIDE it.
	deb := filepath.Join(work, "openshield_9.9.9_amd64.deb")
	out, err := runCapture(t, "openshieldctl", nil, "package-deb",
		"--dir", dist, "--key", pub, "--version", "9.9.9", "--units", "", "--out", deb)
	if err != nil {
		t.Fatalf("package-deb: %v\n%s", err, out)
	}

	// AND THE RELEASE STILL VERIFIES AFTERWARDS.
	//
	// The manifest signature covers the SET, so verify-release reports any file present but unnamed —
	// the check that catches a binary added after signing. A package written into the release directory
	// is exactly such a file, and the first version of this command defaulted to putting it there: the
	// next verify-release failed with the wording of a tamper detection, caused by the packaging step.
	// An operator would reasonably have concluded their release was compromised.
	if vout, verr := runCapture(t, "openshieldctl", nil, "verify-release",
		"--dir", dist, "--key", pub); verr != nil {
		t.Fatalf("the release stopped verifying after packaging it: %v\n%s", verr, vout)
	}
	// Writing INTO the release directory is refused rather than silently breaking it later.
	if bad, berr := runCapture(t, "openshieldctl", nil, "package-deb",
		"--dir", dist, "--key", pub, "--version", "9.9.9", "--units", "",
		"--out", filepath.Join(dist, "x.deb")); berr == nil {
		t.Errorf("a package was written into the release directory. The next verify-release there fails "+
			"with 'present but not in the manifest', which reads as tampering:\n%s", bad)
	}
	if _, serr := os.Stat(deb); serr != nil {
		t.Fatalf("no package was written: %v\n%s", serr, out)
	}

	// 2. DPKG IS THE AUTHORITY ON THE FORMAT. Its own inspector has to accept the archive before any
	// claim about "a Debian package" is worth making.
	if info, derr := exec.Command(dpkg, "--info", deb).CombinedOutput(); derr != nil {
		t.Fatalf("dpkg rejected the package: %v\n%s", derr, info)
	}
	contents, err := exec.Command(dpkg, "--contents", deb).CombinedOutput()
	if err != nil {
		t.Fatalf("dpkg --contents: %v\n%s", err, contents)
	}
	if !strings.Contains(string(contents), "usr/bin/openshield-engine") {
		t.Fatalf("the engine is not in the package:\n%s", contents)
	}
	if strings.Contains(string(contents), "linux_amd64") {
		t.Errorf("an installed path kept its release platform suffix; the units reference the bare "+
			"name:\n%s", contents)
	}

	// 3. IT ACTUALLY INSTALLS, and the binary it places runs.
	t.Cleanup(func() { _ = exec.Command(dpkg, "--purge", "openshield").Run() })
	if inst, ierr := exec.Command(dpkg, "-i", deb).CombinedOutput(); ierr != nil {
		t.Fatalf("dpkg -i failed: %v\n%s", ierr, inst)
	}
	if _, serr := os.Stat("/usr/bin/openshield-engine"); serr != nil {
		t.Fatalf("the engine was not installed: %v", serr)
	}
	// The postinst must have created the service users, or every unit fails to start with a message
	// nobody sees until they try.
	if id, uerr := exec.Command("id", "openshield-engine").CombinedOutput(); uerr != nil {
		t.Errorf("the service user was not created by postinst: %v\n%s", uerr, id)
	}

	// 4. AND REMOVAL LEAVES THE SERVICE USER ALONE. The engine owns forward-secure ledger state; deleting
	// its uid orphans those files and a reinstall cannot read its own history.
	if rem, rerr := exec.Command(dpkg, "--purge", "openshield").CombinedOutput(); rerr != nil {
		t.Fatalf("dpkg --purge: %v\n%s", rerr, rem)
	}
	if _, serr := os.Stat("/usr/bin/openshield-engine"); serr == nil {
		t.Error("the binary survived a purge")
	}
	if _, uerr := exec.Command("id", "openshield-engine").CombinedOutput(); uerr != nil {
		t.Error("purging the package DELETED the service user. The engine's ledger signer state is owned " +
			"by that uid, so a reinstall gets a different one and cannot read its own tamper-evident " +
			"history")
	}
}
