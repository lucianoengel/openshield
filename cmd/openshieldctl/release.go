package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lucianoengel/openshield/internal/release"
)

// PLAT-6: producing and verifying a signed, reproducible artifact set.
//
// Verification lives in the CLI rather than in a README because an instruction nobody runs is not a
// control. `verify-release` re-checks every digest against the signed manifest AND reports a file that is
// present but unnamed — the check a lazy verifier skips, and the one that catches a binary added after
// signing.

// releaseManifest builds and signs the manifest over a release directory.
func releaseManifest(args []string) int {
	fs := flag.NewFlagSet("release-manifest", flag.ContinueOnError)
	dir := fs.String("dir", "dist", "release directory")
	version := fs.String("version", "dev", "release version")
	commit := fs.String("commit", "unknown", "source commit")
	keyPath := fs.String("key", "", "ed25519 private key file (never enters the release output)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "openshieldctl: --key is required; the private key is a path supplied at "+
			"release time and never ships")
		return 2
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: reading signing key: %v\n", err)
		return 1
	}
	if len(key) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "openshieldctl: signing key is %d bytes, want %d (raw ed25519 private key)\n",
			len(key), ed25519.PrivateKeySize)
		return 1
	}
	priv := ed25519.PrivateKey(key)

	// The SBOM is written BEFORE the manifest, so it is digested like any other artifact and the
	// signature covers it. An unsigned SBOM is worthless: anyone can hand you a clean document about
	// someone else's binary.
	sbom, err := release.BuildSBOM(*dir, *version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: building SBOM: %v\n", err)
		return 1
	}
	if err := release.WriteSBOM(*dir, sbom); err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: writing SBOM: %v\n", err)
		return 1
	}

	// The platform is derived from the artifact NAME (cmd_goos_goarch), so each entry states its own
	// rather than the release implying one set of platforms for everything.
	m, err := release.Build(*dir, *version, *commit, runtime.Version(), platformOf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: building manifest: %v\n", err)
		return 1
	}
	sig, err := release.Sign(m, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: signing: %v\n", err)
		return 1
	}
	canonical, err := m.Canonical()
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
		return 1
	}
	for name, body := range map[string][]byte{
		release.ManifestName:  canonical,
		release.SignatureName: sig,
		release.PublicKeyName: priv.Public().(ed25519.PublicKey),
	} {
		if err := os.WriteFile(filepath.Join(*dir, name), body, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "openshieldctl: writing %s: %v\n", name, err)
			return 1
		}
	}
	fmt.Fprintf(os.Stderr, "openshieldctl: signed %d artifact(s) as %s (SBOM covers %d binaries)\n",
		len(m.Entries), *version, len(sbom.Artifacts))
	return 0
}

// verifyRelease checks a release directory. It is the operator-facing half of the ticket.
func verifyRelease(args []string) int {
	fs := flag.NewFlagSet("verify-release", flag.ContinueOnError)
	dir := fs.String("dir", "dist", "release directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	m, err := release.LoadAndVerify(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "verified %d artifact(s): %s (commit %s, built with %s)\n",
		len(m.Entries), m.Version, m.Commit, m.GoVersion)
	return 0
}

// platformOf reads goos/goarch back out of an artifact name built as cmd_goos_goarch.
func platformOf(name string) string {
	parts := strings.Split(strings.TrimSuffix(name, ".exe"), "_")
	if len(parts) < 3 {
		return ""
	}
	return parts[len(parts)-2] + "/" + parts[len(parts)-1]
}
