// Command openshield-fim-baseline is the operator tool for FIM signed baselines (HIPS-4).
//
// It captures a known-good baseline (SHA-256 of each critical file) from operator-designated paths and
// SIGNS it with an operator Ed25519 key, producing the exact bytes openshield-engine verifies
// (OPENSHIELD_FIM_BASELINE_PUBKEY) before trusting it. The node never holds the signing key, so a
// compromised node cannot forge a baseline and a compromised distribution path cannot alter a signed one.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lucianoengel/openshield/internal/fim"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "build":
		build(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `openshield-fim-baseline — capture + sign a FIM known-good baseline (HIPS-4)

  keygen --out-key operator.key --out-pub operator.pub
      Generate a raw Ed25519 operator keypair (64-byte private, 32-byte public).
      Give operator.pub to the engine as OPENSHIELD_FIM_BASELINE_PUBKEY.

  build --paths <comma-separated files/dirs> --key operator.key --out baseline.signed [--max-hash-bytes N]
      Capture a baseline of the paths (SHA-256 of each file) and sign it with operator.key.
      REVIEW the captured files first — the baseline is only as trustworthy as the state at capture.
`)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "openshield-fim-baseline: "+format+"\n", a...)
	os.Exit(1)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outKey := fs.String("out-key", "", "path to write the raw Ed25519 private key (64 bytes)")
	outPub := fs.String("out-pub", "", "path to write the raw Ed25519 public key (32 bytes)")
	_ = fs.Parse(args)
	if *outKey == "" || *outPub == "" {
		fatal("keygen needs --out-key and --out-pub")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generating key: %v", err)
	}
	if err := os.WriteFile(*outKey, priv, 0o600); err != nil {
		fatal("writing private key: %v", err)
	}
	if err := os.WriteFile(*outPub, pub, 0o644); err != nil {
		fatal("writing public key: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (private, keep offline) and %s (public, → OPENSHIELD_FIM_BASELINE_PUBKEY)\n", *outKey, *outPub)
}

func build(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	paths := fs.String("paths", "", "comma-separated critical files/directories to baseline")
	keyPath := fs.String("key", "", "operator Ed25519 private key (from keygen)")
	out := fs.String("out", "", "path to write the signed baseline")
	maxHash := fs.Int64("max-hash-bytes", fim.DefaultMaxHashBytes, "per-file hash cap")
	_ = fs.Parse(args)
	if *paths == "" || *keyPath == "" || *out == "" {
		fatal("build needs --paths, --key and --out")
	}
	priv, err := os.ReadFile(*keyPath)
	if err != nil {
		fatal("reading key: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		fatal("key is %d bytes, want %d (a raw Ed25519 private key)", len(priv), ed25519.PrivateKeySize)
	}
	var list []string
	for _, p := range strings.Split(*paths, ",") {
		if p = strings.TrimSpace(p); p != "" {
			list = append(list, p)
		}
	}
	m, overflow, err := fim.BuildBaseline(list, fim.Options{MaxHashBytes: *maxHash})
	if err != nil {
		fatal("building baseline: %v", err)
	}
	signed, err := fim.SignManifest(m, ed25519.PrivateKey(priv))
	if err != nil {
		fatal("signing baseline: %v", err)
	}
	if err := os.WriteFile(*out, signed, 0o644); err != nil {
		fatal("writing signed baseline: %v", err)
	}
	fmt.Fprintf(os.Stderr, "signed baseline of %d files → %s", m.Size(), *out)
	if overflow > 0 {
		fmt.Fprintf(os.Stderr, " (WARNING: %d files past the cap were not recorded)", overflow)
	}
	fmt.Fprintln(os.Stderr)
}
