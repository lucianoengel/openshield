package debpkg

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lucianoengel/openshield/internal/release"
)

// VERIFYING AN INSTALLATION, NOT AN ARCHIVE.
//
// The release proves that a set of artifacts corresponds to a commit, and the package carries that proof
// onto the machine. This is the part that uses it: given the public key an operator obtained out of band,
// it re-derives every installed binary's digest and compares it to the signed manifest.
//
// It answers a question the product's own threat model says operators must be able to ask — "is what is
// running here what was published?" — about the product itself. A platform that argues for tamper-evidence
// and cannot demonstrate it on its own binaries is making a claim it does not keep.
//
// WHAT IT IS NOT. This is detection, not prevention, and it is not effective against root (D16): anything
// able to replace a binary in /usr/bin can also replace the manifest beside it, and — if it holds the
// operator's key — re-sign. Its value is that doing so requires the SIGNING KEY, which is not on the
// endpoint. An attacker who tampers without it leaves a mismatch that this reports.

// InstallReport is the outcome of checking an installation.
type InstallReport struct {
	Version   string
	Commit    string
	Arch      string
	Checked   int
	Mismatch  []string // installed, digest differs from the signed manifest — tampering or a partial upgrade
	Missing   []string // in the manifest, absent from the installation
	Unlisted  []string // present in the binary directory, named by no manifest entry
	KeyFinger string
}

// OK reports whether the installation matches its manifest exactly.
func (r InstallReport) OK() bool {
	return len(r.Mismatch) == 0 && len(r.Missing) == 0 && len(r.Unlisted) == 0
}

// Error renders the discrepancies. Each category is reported SEPARATELY because they mean different
// things: a mismatch is a changed binary, a missing one is an incomplete install, and an unlisted one is a
// binary somebody added — and only the last is invisible to a verifier that walks the manifest alone.
func (r InstallReport) Error() string {
	var parts []string
	if len(r.Mismatch) > 0 {
		parts = append(parts, "MODIFIED since it was signed: "+strings.Join(r.Mismatch, ", "))
	}
	if len(r.Missing) > 0 {
		parts = append(parts, "named by the manifest but not installed: "+strings.Join(r.Missing, ", "))
	}
	if len(r.Unlisted) > 0 {
		parts = append(parts, "installed but named by no manifest entry: "+strings.Join(r.Unlisted, ", "))
	}
	return strings.Join(parts, "; ")
}

// VerifyInstalled checks an installation rooted at prefix against the manifest the package embedded.
//
// The KEY IS REQUIRED and is never read from the installation. The manifest and its signature sit on the
// same disk as the binaries they vouch for, so trusting a key found beside them would let anyone who
// replaced all three pass — the check would confirm only that the files agree with each other.
func VerifyInstalled(prefix string, pub ed25519.PublicKey) (InstallReport, error) {
	var rep InstallReport
	if len(pub) != ed25519.PublicKeySize {
		return rep, fmt.Errorf("debpkg: a public key obtained OUT OF BAND is required; a key taken from " +
			"the installation would confirm only that the files agree with each other")
	}
	provDir := filepath.Join(prefix, provenanceDir)
	manifestBytes, err := os.ReadFile(filepath.Join(provDir, release.ManifestName))
	if err != nil {
		return rep, fmt.Errorf("debpkg: no signed manifest in this installation (%s). It was not "+
			"installed from an OpenShield package, or the manifest has been removed — and removing it is "+
			"what tampering looks like when the tamperer cannot re-sign: %w", provDir, err)
	}
	sig, err := os.ReadFile(filepath.Join(provDir, release.SignatureName))
	if err != nil {
		return rep, fmt.Errorf("debpkg: no manifest signature in this installation: %w", err)
	}
	archBytes, err := os.ReadFile(filepath.Join(provDir, ArchFile))
	if err != nil {
		return rep, fmt.Errorf("debpkg: the installation does not record its architecture: %w", err)
	}
	arch := strings.TrimSpace(string(archBytes))

	// VERIFY THE SIGNATURE BEFORE READING ANYTHING OUT OF THE MANIFEST. An unverified manifest is
	// attacker-controlled input, and using its contents to decide what to check would let it simply not
	// mention the binary that was replaced.
	m, err := release.VerifyManifestSignature(manifestBytes, sig, pub)
	if err != nil {
		return rep, fmt.Errorf("debpkg: the installed manifest does not verify against this key: %w", err)
	}
	rep.Version, rep.Commit, rep.Arch = m.Version, m.Commit, arch
	rep.KeyFinger = release.Fingerprint(pub)

	binDir := filepath.Join(prefix, binPrefix)
	want := "linux/" + arch
	expected := map[string]string{} // installed name -> digest
	for _, e := range m.Entries {
		if e.Platform != want {
			continue
		}
		expected[installName(filepath.Base(e.Name), arch)] = e.SHA256
	}
	if len(expected) == 0 {
		return rep, fmt.Errorf("debpkg: the manifest names no linux/%s artifacts, so this check would "+
			"pass without examining anything", arch)
	}

	for name, sum := range expected {
		got, derr := fileDigest(filepath.Join(binDir, name))
		if derr != nil {
			rep.Missing = append(rep.Missing, name)
			continue
		}
		rep.Checked++
		if got != sum {
			rep.Mismatch = append(rep.Mismatch, name)
		}
	}

	// AND ANYTHING PRESENT THAT THE MANIFEST DOES NOT NAME. A verifier that only walks the manifest
	// happily ignores an extra openshield binary dropped into /usr/bin — which is the whole reason the
	// release signs the SET rather than each file, and the same omission that check exists to catch
	// upstream.
	ents, err := os.ReadDir(binDir)
	if err != nil {
		return rep, fmt.Errorf("debpkg: reading %s: %w", binDir, err)
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, "openshield") {
			continue
		}
		if _, ok := expected[n]; !ok {
			rep.Unlisted = append(rep.Unlisted, n)
		}
	}

	sort.Strings(rep.Mismatch)
	sort.Strings(rep.Missing)
	sort.Strings(rep.Unlisted)
	return rep, nil
}

func fileDigest(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
