// Package release builds and verifies a signed, reproducible artifact set (PLAT-6).
//
// The thing being shipped runs as root on every endpoint, so "trust me, this tarball is fine" is exactly
// the supply-chain posture this product exists to argue against. Two properties make an artifact
// verifiable, and they depend on each other:
//
//   - REPRODUCIBLE builds. Without them a signature attests only that the signer had *a* binary. With
//     them, anyone can rebuild the commit and confirm the artifact corresponds to the source.
//   - A SIGNED MANIFEST rather than per-artifact signatures. One signature covers the SET, so an artifact
//     cannot be ADDED to a release unnoticed — per-artifact signatures verify each file and say nothing
//     about which files should exist.
//
// ed25519 rather than a new signing toolchain: the platform already signs feeds, intents and risk with it,
// and operators already handle its keys. Keyless signing (Sigstore) is genuinely better for public
// distribution and is a different trust decision — a keyless root, a network dependency, a transparency
// log — not a bigger version of this one, so it is its own ticket rather than a prerequisite for artifacts
// being verifiable at all.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestName and SignatureName are the files a release carries alongside its artifacts.
const (
	ManifestName  = "SHA256SUMS.json"
	SignatureName = "SHA256SUMS.json.sig"
	PublicKeyName = "release-key.pub"
)

// Entry is one artifact.
type Entry struct {
	Name     string `json:"name"`
	Platform string `json:"platform"` // e.g. linux/amd64 — stated per artifact rather than implied
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// Manifest is the signed description of a release.
//
// GoVersion is recorded because the toolchain affects output: a rebuild that does not match is then
// diagnosable rather than mysterious.
type Manifest struct {
	Version   string  `json:"version"`
	Commit    string  `json:"commit"`
	GoVersion string  `json:"go_version"`
	Entries   []Entry `json:"entries"`
}

// Canonical is the exact byte sequence that gets signed. Deterministic (sorted entries, stable field
// order, no trailing whitespace) so a manifest signs and verifies identically on any machine — a
// signature over a non-canonical encoding is a signature over one program's formatting choices.
func (m Manifest) Canonical() ([]byte, error) {
	c := m
	c.Entries = append([]Entry(nil), m.Entries...)
	sort.Slice(c.Entries, func(i, j int) bool { return c.Entries[i].Name < c.Entries[j].Name })
	return json.MarshalIndent(c, "", "  ")
}

// ErrSignature means the manifest is not what was signed.
var ErrSignature = errors.New("release: manifest signature does not verify")

// VerificationError names exactly what did not match. Three failure modes are reported distinctly because
// they mean different things to whoever is holding the download.
type VerificationError struct {
	Missing   []string // named by the manifest, absent from the directory
	Mismatch  []string // present, but the bytes are not what was signed
	Unlisted  []string // present, and the manifest does not name it — the one a lazy verifier skips
	Signature bool
}

func (e *VerificationError) Error() string {
	var parts []string
	if e.Signature {
		parts = append(parts, "manifest signature does not verify")
	}
	if len(e.Mismatch) > 0 {
		parts = append(parts, "digest mismatch: "+strings.Join(e.Mismatch, ", "))
	}
	if len(e.Missing) > 0 {
		parts = append(parts, "missing: "+strings.Join(e.Missing, ", "))
	}
	if len(e.Unlisted) > 0 {
		parts = append(parts, "present but not in the manifest: "+strings.Join(e.Unlisted, ", "))
	}
	return "release verification failed: " + strings.Join(parts, "; ")
}

// digest returns a file's SHA-256 and size.
func digest(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// isMeta reports the release's own bookkeeping files, which are not artifacts and are therefore neither
// listed in the manifest nor reported as unlisted.
func isMeta(name string) bool {
	return name == ManifestName || name == SignatureName || name == PublicKeyName
}

// Build produces a manifest over every artifact in dir.
func Build(dir, version, commit, goVersion string, platform func(name string) string) (Manifest, error) {
	m := Manifest{Version: version, Commit: commit, GoVersion: goVersion}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return m, err
	}
	for _, e := range ents {
		if e.IsDir() || isMeta(e.Name()) {
			continue
		}
		sum, size, err := digest(filepath.Join(dir, e.Name()))
		if err != nil {
			return m, err
		}
		p := ""
		if platform != nil {
			p = platform(e.Name())
		}
		m.Entries = append(m.Entries, Entry{Name: e.Name(), Platform: p, Size: size, SHA256: sum})
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Name < m.Entries[j].Name })
	return m, nil
}

// Sign returns the detached signature over the canonical manifest.
func Sign(m Manifest, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("release: signing key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	canonical, err := m.Canonical()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, canonical), nil
}

// Verify checks a release directory against its manifest and signature.
//
// The SIGNATURE is checked FIRST: if the manifest is not what was signed, the digests it lists are the
// attacker's digests, and verifying files against them would report a healthy release.
func Verify(dir string, manifestBytes, sig []byte, pub ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	if len(pub) != ed25519.PublicKeySize {
		return m, fmt.Errorf("release: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return m, fmt.Errorf("release: unreadable manifest: %w", err)
	}
	canonical, err := m.Canonical()
	if err != nil {
		return m, err
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return m, &VerificationError{Signature: true}
	}

	ve := &VerificationError{}
	listed := make(map[string]bool, len(m.Entries))
	for _, e := range m.Entries {
		listed[e.Name] = true
		sum, size, err := digest(filepath.Join(dir, e.Name))
		if err != nil {
			ve.Missing = append(ve.Missing, e.Name)
			continue
		}
		// Compare the DIGEST, not the size: a size check passes for any tampering that preserves length,
		// which is most of it.
		if sum != e.SHA256 || size != e.Size {
			ve.Mismatch = append(ve.Mismatch, e.Name)
		}
	}
	// AND report anything present that the manifest does not name. A verifier that only walks the manifest
	// happily ignores an extra binary dropped into the directory — which is the whole reason the signature
	// covers the SET rather than each file.
	ents, err := os.ReadDir(dir)
	if err != nil {
		return m, err
	}
	for _, e := range ents {
		if e.IsDir() || isMeta(e.Name()) || listed[e.Name()] {
			continue
		}
		ve.Unlisted = append(ve.Unlisted, e.Name())
	}
	sort.Strings(ve.Missing)
	sort.Strings(ve.Mismatch)
	sort.Strings(ve.Unlisted)
	if len(ve.Missing) > 0 || len(ve.Mismatch) > 0 || len(ve.Unlisted) > 0 {
		return m, ve
	}
	return m, nil
}

// Fingerprint identifies a public key compactly enough to be compared by eye.
//
// A full key in terminal output is unreadable and gets copied wrongly, which matters because the whole
// point of reporting the key is that two operators can establish they verified against the SAME one.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// LoadAndVerifyWithKey verifies a release against a public key the operator obtained OUT OF BAND.
//
// THIS IS THE ONLY WAY TO ESTABLISH AUTHENTICITY, and the reason is structural rather than a matter of
// care: everything in the release directory is under the control of whoever modified the download.
// Verification that reads its key from there answers "is this set internally consistent" — a question an
// attacker who re-signs the whole set with a key of their own can arrange a "yes" to. Only a key from
// somewhere else can answer "did the project sign this".
//
// The shipped key is NOT consulted here, on any condition. A fallback — on an unreadable pin, on a
// mismatch between the two — would reintroduce the entire gap through the error path, and an attacker who
// can modify the download can usually arrange the condition.
func LoadAndVerifyWithKey(dir string, pub ed25519.PublicKey) (Manifest, error) {
	var m Manifest
	if len(pub) != ed25519.PublicKeySize {
		return m, fmt.Errorf("release: pinned public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	manifestBytes, sig, err := loadMeta(dir)
	if err != nil {
		return m, err
	}
	return Verify(dir, manifestBytes, sig, pub)
}

// loadMeta reads the manifest and its signature. Shared so the pinned and unpinned paths cannot drift.
func loadMeta(dir string) (manifestBytes, sig []byte, err error) {
	manifestBytes, err = os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, nil, err
	}
	sig, err = os.ReadFile(filepath.Join(dir, SignatureName))
	if err != nil {
		return nil, nil, err
	}
	return manifestBytes, sig, nil
}

// LoadAndVerify is the operator-facing path: read the manifest, signature and public key from a release
// directory and check it. Verification should be a command someone runs, not a paragraph in a README.
//
// IT CHECKS INTEGRITY, NOT AUTHENTICITY — see LoadAndVerifyWithKey. It reads the key from the directory
// it is verifying, so it establishes that the artifact set matches one signature, not whose. That is
// worth having (it catches every corruption and every post-signing edit) and it is strictly less than an
// operator reading "verified" is likely to assume, which is why the command says so.
func LoadAndVerify(dir string) (Manifest, error) {
	var m Manifest
	manifestBytes, sig, err := loadMeta(dir)
	if err != nil {
		return m, err
	}
	pub, err := os.ReadFile(filepath.Join(dir, PublicKeyName))
	if err != nil {
		return m, err
	}
	return Verify(dir, manifestBytes, sig, ed25519.PublicKey(pub))
}
