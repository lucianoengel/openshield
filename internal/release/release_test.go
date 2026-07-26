package release_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/release"
)

// PLAT-6. The two properties that make an artifact verifiable, and they depend on each other:
// reproducible builds, and a signature over the SET rather than over each file.

func stageRelease(t *testing.T) (dir string, pub ed25519.PublicKey, priv ed25519.PrivateKey) { //nolint:unparam
	t.Helper()
	dir = t.TempDir()
	for name, body := range map[string]string{
		"openshield-server": "server-binary-bytes",
		"openshield-agent":  "agent-binary-bytes",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := release.Build(dir, "v0.1.0", "abc123", "go1.24", func(string) string { return "linux/amd64" })
	if err != nil {
		t.Fatal(err)
	}
	sig, err := release.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := m.Canonical()
	write(t, dir, release.ManifestName, canonical)
	write(t, dir, release.SignatureName, sig)
	write(t, dir, release.PublicKeyName, pub)
	return dir, pub, priv
}

func write(t *testing.T, dir, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAValidReleaseVerifies(t *testing.T) {
	dir, _, _ := stageRelease(t)
	m, err := release.LoadAndVerify(dir)
	if err != nil {
		t.Fatalf("a freshly built release did not verify: %v", err)
	}
	if len(m.Entries) != 2 || m.Version != "v0.1.0" || m.GoVersion == "" {
		t.Errorf("manifest = %+v, want both artifacts and the build metadata", m)
	}
	// Every entry names its platform rather than the release implying one.
	for _, e := range m.Entries {
		if e.Platform == "" || e.SHA256 == "" {
			t.Errorf("entry %+v is missing its platform or digest", e)
		}
	}
	// THE SIGNING KEY NEVER SHIPS.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		body, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if len(body) == ed25519.PrivateKeySize && e.Name() != release.SignatureName {
			t.Errorf("%s is private-key sized — the signing key must never appear in the output", e.Name())
		}
	}
}

// TestTamperingIsDetected covers all three failure modes, each meaning something different to whoever is
// holding the download.
//
// Mutation: compare sizes instead of digests → the same-length edit passes → FAILS.
// Mutation: iterate manifest entries only → the unlisted extra binary is ignored → FAILS.
func TestTamperingIsDetected(t *testing.T) {
	t.Run("modified artifact", func(t *testing.T) {
		dir, _, _ := stageRelease(t)
		// SAME LENGTH as the original, so only a digest comparison catches it.
		write(t, dir, "openshield-server", []byte("server-binary-BYTES"))
		_, err := release.LoadAndVerify(dir)
		if err == nil {
			t.Fatal("a modified artifact verified — a same-length edit is most tampering")
		}
		if !strings.Contains(err.Error(), "openshield-server") {
			t.Errorf("the failure does not name the artifact: %v", err)
		}
	})
	t.Run("modified manifest", func(t *testing.T) {
		dir, _, _ := stageRelease(t)
		body, _ := os.ReadFile(filepath.Join(dir, release.ManifestName))
		var m release.Manifest
		_ = json.Unmarshal(body, &m)
		m.Entries[0].SHA256 = strings.Repeat("0", 64) // an attacker's digest for their binary
		c, _ := m.Canonical()
		write(t, dir, release.ManifestName, c)
		_, err := release.LoadAndVerify(dir)
		if err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("an altered manifest was accepted: %v — the digests it lists would be the "+
				"attacker's, so the signature must be checked FIRST", err)
		}
	})
	t.Run("unlisted extra file", func(t *testing.T) {
		dir, _, _ := stageRelease(t)
		write(t, dir, "openshield-backdoor", []byte("extra"))
		_, err := release.LoadAndVerify(dir)
		if err == nil {
			t.Fatal("an artifact ADDED after signing was ignored — a verifier that only walks the " +
				"manifest happily accepts an extra binary, which is why the signature covers the SET")
		}
		if !strings.Contains(err.Error(), "openshield-backdoor") {
			t.Errorf("the failure does not name the extra file: %v", err)
		}
	})
	t.Run("consistently replaced artifact and manifest", func(t *testing.T) {
		// THE CASE ONLY THE SIGNATURE CATCHES, and the one the first version of this test missed: an
		// attacker who swaps a binary AND regenerates the manifest to match it. Every digest then agrees
		// with every file, so digest checking alone reports a healthy release.
		dir, _, _ := stageRelease(t)
		write(t, dir, "openshield-server", []byte("attacker-supplied-binary"))
		m, err := release.Build(dir, "v0.1.0", "abc123", "go1.24", func(string) string { return "linux/amd64" })
		if err != nil {
			t.Fatal(err)
		}
		c, _ := m.Canonical()
		write(t, dir, release.ManifestName, c) // consistent, but signed by nobody
		_, err = release.LoadAndVerify(dir)
		if err == nil {
			t.Fatal("a consistently-replaced release verified — every digest matched its file, so only " +
				"the SIGNATURE distinguishes this from a genuine release")
		}
		if !strings.Contains(err.Error(), "signature") {
			t.Errorf("the failure does not identify the signature as the thing that did not hold: %v", err)
		}
	})
	t.Run("missing artifact", func(t *testing.T) {
		dir, _, _ := stageRelease(t)
		os.Remove(filepath.Join(dir, "openshield-agent"))
		_, err := release.LoadAndVerify(dir)
		if err == nil || !strings.Contains(err.Error(), "openshield-agent") {
			t.Errorf("a missing artifact was not reported: %v", err)
		}
	})
}

// TestReleaseBuildIsReproducible is the property the signature is worth something BECAUSE of: without it,
// a signature attests only that the signer had *a* binary, and nobody but the signer can establish that an
// artifact corresponds to the source.
//
// Scoped to one command rather than the whole tree, so the cost is a few seconds.
func TestReleaseBuildIsReproducible(t *testing.T) {
	if testing.Short() {
		t.Skip("builds twice")
	}
	build := func(out string) string {
		t.Helper()
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false",
			"-ldflags", "-s -w -X main.version=v0.1.0-test", "-o", out,
			"github.com/lucianoengel/openshield/cmd/openshield-anchor")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("release build failed: %v\n%s", err, out)
		}
		m, err := release.Build(filepath.Dir(out), "v", "c", "g", nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Entries) != 1 {
			t.Fatalf("expected one artifact, got %d", len(m.Entries))
		}
		return m.Entries[0].SHA256
	}
	first := build(filepath.Join(t.TempDir(), "openshield-anchor"))
	second := build(filepath.Join(t.TempDir(), "openshield-anchor"))
	if first != second {
		t.Errorf("two builds of the same commit differ (%s vs %s) — a signature over a non-reproducible "+
			"artifact attests only that the signer had A binary, not that it came from this source",
			first[:16], second[:16])
	}
}

// TestSBOMIsCoveredByTheSignature is the property that makes an SBOM evidence rather than paperwork.
//
// An UNSIGNED SBOM is worthless — anyone can hand you a clean document about someone else's binary — so it
// is written into the release directory BEFORE the manifest, digested like any other artifact.
//
// Mutation: write the SBOM AFTER the manifest is built → it becomes an unlisted extra file (or, if also
// excluded from verification, an unsigned document) → FAILS.
func TestSBOMIsCoveredByTheSignature(t *testing.T) {
	dir, _, priv := stageRelease(t)
	// Re-stage with an SBOM present before the manifest, as the real release path does.
	sbom, err := release.BuildSBOM(dir, "v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := release.WriteSBOM(dir, sbom); err != nil {
		t.Fatal(err)
	}
	m, err := release.Build(dir, "v0.1.0", "abc123", "go1.24", func(string) string { return "linux/amd64" })
	if err != nil {
		t.Fatal(err)
	}
	sig, err := release.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := m.Canonical()
	write(t, dir, release.ManifestName, canonical)
	write(t, dir, release.SignatureName, sig)

	if _, err := release.LoadAndVerify(dir); err != nil {
		t.Fatalf("a release with an SBOM did not verify: %v", err)
	}
	var listed bool
	for _, e := range m.Entries {
		if e.Name == release.SBOMName {
			listed = true
		}
	}
	if !listed {
		t.Fatal("the SBOM is not in the manifest — it is then a document anyone can swap for a clean one")
	}
	// Tampering with it must fail, which is the whole point of covering it.
	write(t, dir, release.SBOMName, []byte(`{"format":"openshield-sbom/v1","artifacts":[]}`))
	if _, err := release.LoadAndVerify(dir); err == nil {
		t.Error("a REPLACED SBOM verified — an SBOM that can be swapped after signing attests nothing")
	}
}

// TestSBOMDescribesWhatSHIPPED, not what was intended: it is read from the binary's recorded module
// graph, so a go.mod that disagrees with the artifact cannot hide behind the document.
func TestSBOMDescribesWhatShipped(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "openshield-anchor_linux_amd64")
	cmd := exec.Command("go", "build", "-trimpath", "-o", out,
		"github.com/lucianoengel/openshield/cmd/openshield-anchor")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, o)
	}
	s, err := release.BuildSBOM(dir, "v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Artifacts) != 1 {
		t.Fatalf("SBOM covers %d artifacts, want 1", len(s.Artifacts))
	}
	a := s.Artifacts[0]
	if a.GoVersion == "" || a.Main == "" {
		t.Errorf("SBOM entry lacks build metadata: %+v", a)
	}
	if len(a.Components) == 0 {
		t.Error("SBOM lists no components — read from the binary's recorded module graph, a real build " +
			"has dependencies; an empty list means it was not actually read")
	}
	for _, c := range a.Components {
		if c.Name == "" || c.Version == "" {
			t.Errorf("component with no name or version: %+v", c)
		}
	}
}
