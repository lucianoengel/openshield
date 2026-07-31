package debpkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFromPackage unpacks a built package into a temporary root, exactly as dpkg would place it. Going
// through the real package rather than assembling a directory by hand is the point: it proves the
// provenance an installed system needs actually TRAVELS in the package.
func installFromPackage(t *testing.T, pkg *Package) string {
	t.Helper()
	root := t.TempDir()
	zr, err := gzip.NewReader(bytes.NewReader(members(t, pkg.Bytes)["data.tar.gz"]))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		dest := filepath.Join(root, strings.TrimPrefix(h.Name, "./"))
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, body, os.FileMode(h.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func installed(t *testing.T) (root string, pub ed25519.PublicKey) {
	t.Helper()
	s := spec(t)
	pkg, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	return installFromPackage(t, pkg), s.PublicKey
}

// AN UNTOUCHED INSTALLATION VERIFIES, and says which release it is.
//
// This is the product's own tamper-evidence claim, asked about the product: an operator holding the
// public key can establish that what is on the machine is what was published.
func TestAnUntouchedInstallationVerifiesAgainstItsRelease(t *testing.T) {
	root, pub := installed(t)
	rep, err := VerifyInstalled(root, pub)
	if err != nil {
		t.Fatalf("a freshly unpacked package did not verify: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("a freshly unpacked package reported discrepancies: %s", rep.Error())
	}
	if rep.Checked == 0 {
		t.Fatal("nothing was checked, so this passed without examining anything")
	}
	if rep.Version != "1.2.3" {
		t.Errorf("version = %q, want the release's", rep.Version)
	}
}

// A MODIFIED BINARY IS CAUGHT. The headline.
//
// Mutation (compare sizes instead of digests): a same-length replacement passes → this uses a
// same-length payload deliberately, so the size check alone cannot save it.
func TestAModifiedBinaryIsDetected(t *testing.T) {
	root, pub := installed(t)
	victim := filepath.Join(root, binPrefix, "openshield-engine")
	original, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	// SAME LENGTH, different bytes — the shape most tampering takes, and the case a size comparison
	// cannot see.
	tampered := append([]byte{}, original...)
	tampered[0] ^= 0xff
	if err := os.WriteFile(victim, tampered, 0o755); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifyInstalled(root, pub)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("a MODIFIED binary passed verification. The one question this command exists to answer " +
			"is whether what is running here is what was published, and it answered yes about a file " +
			"that had been changed")
	}
	if len(rep.Mismatch) != 1 || rep.Mismatch[0] != "openshield-engine" {
		t.Fatalf("mismatch = %v, want exactly the modified binary", rep.Mismatch)
	}
}

// A BINARY ADDED AFTER INSTALLATION IS CAUGHT.
//
// A verifier that walks only the manifest confirms every listed file and never notices an extra one — so
// an attacker adds rather than replaces, and the check reports success. It is the same omission the
// release's own verifier guards against upstream, and it has to be guarded here too or the property is
// lost at the point it matters most.
func TestABinaryAddedAfterInstallationIsDetected(t *testing.T) {
	root, pub := installed(t)
	if err := os.WriteFile(filepath.Join(root, binPrefix, "openshield-backdoor"),
		[]byte("#!/bin/sh\nexec /bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyInstalled(root, pub)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("an extra openshield binary dropped into the install directory passed verification. " +
			"Adding is easier than replacing, so a verifier that only walks the manifest is one an " +
			"attacker simply steps around")
	}
	if len(rep.Unlisted) != 1 || rep.Unlisted[0] != "openshield-backdoor" {
		t.Fatalf("unlisted = %v, want the added binary", rep.Unlisted)
	}
}

// A DELETED BINARY IS REPORTED AS MISSING, distinctly from one that was changed.
//
// The categories mean different things — a partial upgrade, a failed install and a replaced file need
// different responses — and collapsing them into "failed" makes the report useless for deciding what to
// do next.
func TestARemovedBinaryIsReportedAsMissingRatherThanModified(t *testing.T) {
	root, pub := installed(t)
	if err := os.Remove(filepath.Join(root, binPrefix, "openshield-gateway")); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyInstalled(root, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Missing) != 1 || rep.Missing[0] != "openshield-gateway" {
		t.Fatalf("missing = %v, want the removed binary", rep.Missing)
	}
	if len(rep.Mismatch) != 0 {
		t.Errorf("a removed file was also reported as modified (%v) — the categories have to stay "+
			"distinct or the report cannot guide a response", rep.Mismatch)
	}
}

// THE KEY IS NEVER TAKEN FROM THE INSTALLATION.
//
// The manifest and its signature sit on the same disk as the binaries they vouch for. Trusting a key
// found beside them would let anyone who replaced all three pass — the check would then confirm only that
// the files agree with each other, which is exactly what an attacker would arrange.
func TestVerificationRequiresAKeyTheOperatorSupplies(t *testing.T) {
	root, _ := installed(t)
	if _, err := VerifyInstalled(root, nil); err == nil {
		t.Fatal("verification proceeded with no key")
	}
	// And a DIFFERENT key must not verify, or the signature check is decorative.
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyInstalled(root, other); err == nil {
		t.Fatal("an installation verified against a key that did not sign it")
	}
}

// REMOVING THE MANIFEST IS AN ERROR, NOT A PASS.
//
// It is also what tampering looks like when the tamperer cannot re-sign: delete the evidence and hope the
// check treats its absence as nothing to check. "No manifest" and "manifest matches" must never produce
// the same exit status.
func TestAnInstallationWithNoManifestFailsRatherThanPasses(t *testing.T) {
	root, pub := installed(t)
	if err := os.Remove(filepath.Join(root, provenanceDir, "SHA256SUMS.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyInstalled(root, pub); err == nil {
		t.Fatal("an installation with its manifest deleted verified successfully. Deleting the evidence " +
			"is the cheapest attack available to anyone who cannot re-sign it")
	}
}
