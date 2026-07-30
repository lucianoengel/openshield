package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/fim"
)

// THE CONTRACT IS CROSS-BINARY, so the test is too.
//
// This tool's stated purpose is "producing the exact bytes openshield-engine verifies
// (OPENSHIELD_FIM_BASELINE_PUBKEY) before trusting it". Testing that it writes SOME signed file proves
// nothing about that — the only assertion worth making is that what this binary writes is what the ENGINE
// loads, so this feeds its output to fim.LoadSignedManifest, the exact call at
// cmd/openshield-engine/main.go:395.
//
// The whole security argument depends on it: "the node never holds the signing key, so a compromised node
// cannot forge a baseline and a compromised distribution path cannot alter a signed one."

func keygenInto(t *testing.T, dir string) (keyPath, pubPath string) {
	t.Helper()
	keyPath = filepath.Join(dir, "operator.key")
	pubPath = filepath.Join(dir, "operator.pub")
	keygen([]string{"--out-key", keyPath, "--out-pub", pubPath})
	return keyPath, pubPath
}

func TestKeygenWritesAUsableKeypairAndGuardsThePrivateHalf(t *testing.T) {
	dir := t.TempDir()
	keyPath, pubPath := keygenInto(t, dir)

	priv, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	// The two halves must actually belong together, or the operator distributes a public key that
	// verifies nothing they sign.
	if !bytes.Equal(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey), pub) {
		t.Fatal("the written public key is not the public half of the written private key")
	}

	// The private key is the whole authority here: whoever holds it can mint a baseline the engine
	// trusts. It must not be readable by other local accounts.
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("the operator private key is mode %04o — readable by group or other, and it is the key "+
			"that lets anyone forge a baseline the engine will trust", perm)
	}
}

// The end-to-end contract: keygen -> build -> the ENGINE's own loader accepts it.
func TestASignedBaselineIsAcceptedByTheEnginesLoader(t *testing.T) {
	dir := t.TempDir()
	keyPath, pubPath := keygenInto(t, dir)

	watched := filepath.Join(dir, "critical")
	if err := os.MkdirAll(watched, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"sshd_config": "PermitRootLogin no\n",
		"passwd":      "root:x:0:0::/root:/bin/sh\n",
	} {
		if err := os.WriteFile(filepath.Join(watched, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out := filepath.Join(dir, "baseline.signed")
	build([]string{"--paths", watched, "--key", keyPath, "--out", out})

	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	// THE ENGINE'S CALL, verbatim.
	m, err := fim.LoadSignedManifest(out, ed25519.PublicKey(pub))
	if err != nil {
		t.Fatalf("the engine's loader rejected a baseline this tool just signed: %v\n\n"+
			"These two binaries have to agree byte for byte; if they drift, FIM silently stops having a "+
			"trusted baseline and the engine reports no drift because it has nothing to compare against", err)
	}
	if m.Size() != 2 {
		t.Fatalf("the baseline holds %d files, want the 2 that were captured", m.Size())
	}

	// The signing key must not be anywhere in the artifact that gets distributed.
	signed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(signed, privBytes[:ed25519.SeedSize]) {
		t.Fatal("the signed baseline contains the operator's private key seed — the artifact is " +
			"distributed to every node, and the key is what lets a holder forge a baseline")
	}
}

// The signature has to be LOAD-BEARING. A baseline that verified regardless would leave a compromised
// distribution path free to rewrite what "known-good" means, which is the exact threat the signing exists
// to answer.
func TestATamperedOrForeignlySignedBaselineIsRejected(t *testing.T) {
	dir := t.TempDir()
	keyPath, pubPath := keygenInto(t, dir)

	watched := filepath.Join(dir, "critical")
	if err := os.MkdirAll(watched, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(watched, "f"), []byte("known good\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "baseline.signed")
	build([]string{"--paths", watched, "--key", keyPath, "--out", out})

	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a flipped byte is detected", func(t *testing.T) {
		for _, at := range []int{0, len(signed) / 2, len(signed) - 1} {
			tampered := append([]byte(nil), signed...)
			tampered[at] ^= 0x01
			p := filepath.Join(t.TempDir(), "tampered.signed")
			if err := os.WriteFile(p, tampered, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := fim.LoadSignedManifest(p, ed25519.PublicKey(pub)); err == nil {
				t.Fatalf("a baseline with byte %d flipped was accepted", at)
			}
		}
	})

	t.Run("another operator's key does not verify it", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fim.LoadSignedManifest(out, otherPub); err == nil {
			t.Fatal("a baseline verified against a public key that did not sign it — the signature is " +
				"not binding the baseline to its operator")
		}
	})

	t.Run("an empty public key does not verify it", func(t *testing.T) {
		if _, err := fim.LoadSignedManifest(out, nil); err == nil {
			t.Fatal("a baseline verified against no key at all")
		}
	})
}
