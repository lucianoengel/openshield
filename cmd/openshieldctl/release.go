package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lucianoengel/openshield/internal/debpkg"
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
	keyPath := fs.String("key", "", "ed25519 PUBLIC key obtained out of band; without it, authenticity "+
		"is not established")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var (
		m    release.Manifest
		used ed25519.PublicKey
		err  error
	)
	if *keyPath != "" {
		// A PROBLEM WITH THE PINNED KEY IS FATAL, never a fallback to the key inside the release. Falling
		// back would reintroduce the whole gap through the error path, and an attacker who can modify the
		// download can usually arrange the condition that triggers it.
		key, rerr := os.ReadFile(*keyPath)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "openshieldctl: reading the pinned public key: %v\n", rerr)
			return 1
		}
		if len(key) != ed25519.PublicKeySize {
			fmt.Fprintf(os.Stderr, "openshieldctl: the pinned key is %d bytes, want %d (raw ed25519 public "+
				"key)\n", len(key), ed25519.PublicKeySize)
			return 1
		}
		used = ed25519.PublicKey(key)
		m, err = release.LoadAndVerifyWithKey(*dir, used)
	} else {
		m, err = release.LoadAndVerify(*dir)
		if err == nil {
			used, _ = os.ReadFile(filepath.Join(*dir, release.PublicKeyName))
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "verified %d artifact(s): %s (commit %s, built with %s) against key %s\n",
		len(m.Entries), m.Version, m.Commit, m.GoVersion, release.Fingerprint(used))
	if *keyPath == "" {
		// SAY WHAT WAS NOT ESTABLISHED. An operator who runs a verification command and sees success will
		// believe the strongest claim it could plausibly be making — so a limit that is not stated becomes
		// a false belief, which is the D31 rule applied to the supply chain. This check read its key from
		// the directory it was checking: an attacker who re-signs the set with a key of their own passes it.
		fmt.Fprintf(os.Stderr, "openshieldctl: INTEGRITY only — the artifact set matches a signature made "+
			"by the key SHIPPED WITH IT, which does not establish that the project signed this release. "+
			"Re-run with --key <path to the project's public key, obtained out of band> to check "+
			"authenticity.\n")
	}
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

// buildDeb packages a VERIFIED release directory as a Debian package (PLAT-6 increment 2).
//
// The gap it closes is embarrassing and real: deploy/install.sh runs `go build` on the target host, so an
// operator following the documented path installs binaries that were never signed and never verified —
// while this project's README argues at length that that is the posture to refuse. It also puts a Go
// toolchain on every endpoint.
//
// THE KEY IS REQUIRED, with no fall back to the one inside the release. Falling back would let whoever
// produced the directory also produce the key that vouches for it, which establishes nothing — the same
// reasoning verify-release already applies to its own pinned key.
func buildDeb(args []string) int {
	fs := flag.NewFlagSet("package-deb", flag.ContinueOnError)
	dir := fs.String("dir", "dist", "release directory (must verify)")
	keyPath := fs.String("key", "", "ed25519 PUBLIC key obtained out of band (REQUIRED)")
	version := fs.String("version", "", "package version")
	arch := fs.String("arch", "amd64", "Debian architecture: amd64 or arm64")
	units := fs.String("units", "deploy/systemd", "directory of systemd units to ship")
	out := fs.String("out", "", "output path (default: ./<name>_<version>_<arch>.deb — deliberately NOT "+
		"inside the release directory, see below)")
	maintainer := fs.String("maintainer", "OpenShield <security@openshield.invalid>", "package maintainer")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "openshieldctl: --key is required. A package built from an unverified "+
			"directory launders unattested binaries into a format dpkg installs without asking.")
		return 2
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: reading the public key: %v\n", err)
		return 1
	}
	if len(key) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "openshieldctl: the key is %d bytes, want %d (raw ed25519 public key)\n",
			len(key), ed25519.PublicKeySize)
		return 1
	}
	v := *version
	if v == "" {
		m, merr := release.LoadAndVerifyWithKey(*dir, ed25519.PublicKey(key))
		if merr != nil {
			fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", merr)
			return 1
		}
		v = m.Version
	}

	pkg, err := debpkg.Build(debpkg.Spec{
		Name: "openshield", Version: v, Arch: *arch,
		Maintainer:  *maintainer,
		Description: "OpenShield data security platform (pipeline-native XDR and DLP)",
		Dir:         *dir,
		PublicKey:   ed25519.PublicKey(key),
		UnitDir:     *units,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
		return 1
	}
	// THE PACKAGE MUST NOT LAND INSIDE THE RELEASE DIRECTORY.
	//
	// The signature covers the SET, so verify-release reports any file that is present but not in the
	// manifest — the check that catches a binary added after signing. A .deb written into dist/ is
	// exactly such a file, so the very next verify-release FAILS, and it fails with the wording of a
	// tamper detection. An operator would reasonably conclude their release had been compromised by
	// their own packaging step.
	//
	// The first version of this command defaulted to dist/ and did precisely that.
	dest := *out
	if dest == "" {
		dest = pkg.Filename
	}
	if inside, ierr := isInside(*dir, dest); ierr == nil && inside {
		fmt.Fprintf(os.Stderr, "openshieldctl: refusing to write %s inside the release directory %s.\n"+
			"The manifest signature covers the SET, so an unlisted file there makes verify-release fail "+
			"with 'present but not in the manifest' — the wording of a tamper detection, caused by this "+
			"command. Write it elsewhere.\n", dest, *dir)
		return 2
	}
	if err := os.WriteFile(dest, pkg.Bytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: writing the package: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "built %s from a VERIFIED release (%d files)\n", dest, len(pkg.Files))
	// SAY WHAT INSTALLING WILL AND WILL NOT DO. An operator who installs a security package and sees no
	// output reasonably assumes it is now protecting the machine.
	fmt.Fprintln(os.Stdout, "installing it creates the service users and places the units; it enables "+
		"and starts NOTHING — that stays the operator's decision.")
	// SAY WHAT THE PACKAGE DOES NOT CARRY. Its contents were verified when it was built; the file itself
	// is not signed and nothing downstream re-checks it. The attested unit is the release directory, and
	// an operator moving only the .deb around is trusting however they moved it.
	fmt.Fprintln(os.Stdout, "the package's CONTENTS were verified against the signed manifest at build "+
		"time; the .deb file itself carries no signature, so distributing it alone rests on how it is "+
		"transported.")
	return 0
}

// isInside reports whether path p resolves to somewhere within dir.
func isInside(dir, p string) (bool, error) {
	ad, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	ap, err := filepath.Abs(p)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(ad, ap)
	if err != nil {
		return false, err
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

// verifyInstall checks a live installation against the signed manifest its package embedded.
//
// The product argues that operators should be able to establish what is running on their machines. This
// asks that question about OpenShield itself: every installed binary is re-hashed and compared to the
// release it came from, using a key the operator holds rather than one found on the machine.
//
// It is DETECTION, not prevention, and not effective against root (D16) — anything able to replace a
// binary can remove the manifest beside it. What it costs an attacker is the SIGNING KEY, which is not on
// the endpoint: tampering without it leaves a mismatch this reports.
func verifyInstall(args []string) int {
	fs := flag.NewFlagSet("verify-install", flag.ContinueOnError)
	prefix := fs.String("prefix", "/", "installation root")
	keyPath := fs.String("key", "", "ed25519 PUBLIC key obtained out of band (REQUIRED)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "openshieldctl: --key is required. A key read from the installation "+
			"would confirm only that the files there agree with each other, which is what an attacker "+
			"who replaced all of them would arrange.")
		return 2
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: reading the public key: %v\n", err)
		return 1
	}
	if len(key) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "openshieldctl: the key is %d bytes, want %d (raw ed25519 public key)\n",
			len(key), ed25519.PublicKeySize)
		return 1
	}

	rep, err := debpkg.VerifyInstalled(*prefix, ed25519.PublicKey(key))
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
		return 1
	}
	if !rep.OK() {
		fmt.Fprintf(os.Stderr, "openshieldctl: THIS INSTALLATION DOES NOT MATCH THE RELEASE IT CLAIMS "+
			"TO BE: %s\n", rep.Error())
		return 1
	}
	fmt.Fprintf(os.Stdout, "installation verified: %d binaries match release %s (commit %s, %s) "+
		"against key %s\n", rep.Checked, rep.Version, rep.Commit, rep.Arch, rep.KeyFinger)
	// SAY WHAT THIS DOES NOT ESTABLISH. An operator who runs a verification command and sees success
	// believes the strongest claim it could plausibly be making.
	fmt.Fprintln(os.Stdout, "this is DETECTION, not prevention: root on this host can replace a binary "+
		"AND the manifest beside it. What it cannot do without the signing key is make them agree.")
	return 0
}
