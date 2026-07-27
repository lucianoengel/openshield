package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/nips"
)

// THE GATEWAY'S IOC FEED IS VERIFIABLE (D297).
//
// The control plane verifies the threat-intel feed it INGESTS (SOAR-5). The gateway — the component that
// actually BLOCKS on those indicators — read its own feed unverified, while `nips.LoadSignedFeed` sat
// with no caller. These tests pin the loader's behaviour against the exact artifacts an operator
// produces, because a signature check that accepts a tampered feed is worse than none: it reports
// verification.

func writeFeed(t *testing.T, dir, body string, key ed25519.PrivateKey) string {
	t.Helper()
	p := filepath.Join(dir, "ioc.feed")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if key != nil {
		if err := os.WriteFile(p+".sig", ed25519.Sign(key, []byte(body)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

const feedBody = "domain evil.example\nip 203.0.113.7\n"

func TestASignedIOCFeedLoads(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := writeFeed(t, dir, feedBody, priv)
	feed, _, err := nips.LoadSignedFeed(p, p+".sig", pub, nips.FormatNative)
	if err != nil {
		t.Fatalf("a correctly signed feed was refused: %v", err)
	}
	if feed.Size() == 0 {
		t.Error("the verified feed parsed to nothing")
	}
}

// TestATamperedIOCFeedIsRefusedWholesale is the property that matters.
//
// Not merely that a bad signature errors — that the feed is refused AS A WHOLE. A partially-loaded feed
// is an attacker's best outcome: drop the indicators that would catch them, keep the rest, and the
// gateway looks armed.
func TestATamperedIOCFeedIsRefusedWholesale(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := writeFeed(t, dir, feedBody, priv)
	// The classic attack: REMOVE an indicator. The signature no longer matches.
	if err := os.WriteFile(p, []byte("ip 203.0.113.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	feed, _, err := nips.LoadSignedFeed(p, p+".sig", pub, nips.FormatNative)
	if err == nil {
		t.Fatal("a TAMPERED feed loaded — dropping the indicator that would catch you is the quieter " +
			"attack, and it must fail the signature")
	}
	if feed != nil {
		t.Error("a refused feed still returned indicators — verification must refuse the whole feed")
	}
}

func TestAFeedSignedByAnotherKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := writeFeed(t, dir, feedBody, priv)
	if _, _, err := nips.LoadSignedFeed(p, p+".sig", otherPub, nips.FormatNative); err == nil {
		t.Error("a feed signed by an UNTRUSTED key was accepted")
	}
}

// TestAMissingSignatureIsRefusedWhenAKeyIsConfigured — an operator who configured verification must not
// silently get an unverified load because the .sig file is absent.
func TestAMissingSignatureIsRefusedWhenAKeyIsConfigured(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := writeFeed(t, dir, feedBody, nil) // no .sig written
	if _, _, err := nips.LoadSignedFeed(p, p+".sig", pub, nips.FormatNative); err == nil {
		t.Error("a feed with NO signature loaded while a key was configured — configuring verification " +
			"and getting none is the failure mode that looks safest")
	}
}
