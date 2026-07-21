// Command openshieldctl queries the audit ledger.
//
// It is a READ surface. It holds no signer and can produce no entry — the same
// asymmetry that lets any auditor verify the ledger without the power to forge
// it (D30). It authenticates no operator and records no viewer: until identity
// (T-017) exists there is nobody to name, and a "viewed by <unknown>" entry
// would misrepresent the D20 accountability trail as present when it is not.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/lucianoengel/openshield/internal/cli"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

const usage = `openshieldctl — query the OpenShield audit ledger

usage:
  openshieldctl timeline [--subject S] [--event E] [--since RFC3339] [--until RFC3339] [--anchor FILE]
  openshieldctl verify   [--anchor FILE] [--witness FILE]
  openshieldctl anchor export                        (reads the stored anchor, writes PEM)

connection:
  --dsn  or  OPENSHIELD_DSN   (default: postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable)

exit codes:
  0 consistent   3 tampered   4 unavailable / usage error
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return cli.ExitUnavailable
	}

	cmd := args[0]
	fs := newFlags()
	sub := parseSubject(cmd, args[1:])
	if err := fs.parse(sub.rest); err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n\n%s", err, usage)
		return cli.ExitUnavailable
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch cmd {
	case "timeline":
		anchor, err := loadAnchor(fs.anchor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
			return cli.ExitUnavailable
		}
		r, err := postgres.OpenForVerify(ctx, fs.dsn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
			return cli.ExitUnavailable
		}
		defer r.Close()
		f := cli.Filter{Subject: fs.subject, EventID: fs.event, Since: fs.since, Until: fs.until}
		return cli.Timeline(ctx, os.Stdout, r, anchor, f)

	case "verify":
		anchor, err := loadAnchor(fs.anchor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
			return cli.ExitUnavailable
		}
		r, err := postgres.OpenForVerify(ctx, fs.dsn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
			return cli.ExitUnavailable
		}
		defer r.Close()
		// A witness public key lets verification report COMPLETENESS against the
		// external anchor (D64). Without it, verification is the honest UNVERIFIED
		// degraded mode. openshieldctl stays read-only — this only reads.
		if fs.witness != "" {
			wpub, werr := loadWitnessPub(fs.witness)
			if werr != nil {
				fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", werr)
				return cli.ExitUnavailable
			}
			r.WitnessPub = wpub
		}
		return cli.Verify(ctx, os.Stdout, r, anchor)

	case "anchor":
		if sub.verb != "export" {
			fmt.Fprint(os.Stderr, usage)
			return cli.ExitUnavailable
		}
		return exportAnchor(ctx, fs.dsn)

	default:
		fmt.Fprint(os.Stderr, usage)
		return cli.ExitUnavailable
	}
}

func exportAnchor(ctx context.Context, dsn string) int {
	r, err := postgres.OpenForVerify(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
		return cli.ExitUnavailable
	}
	defer r.Close()
	anchor, err := r.StoredAnchor(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
		return cli.ExitUnavailable
	}
	if err := cli.ExportAnchor(os.Stdout, anchor); err != nil {
		fmt.Fprintf(os.Stderr, "openshieldctl: %v\n", err)
		return cli.ExitUnavailable
	}
	return cli.ExitOK
}

// loadWitnessPub reads a raw 32-byte Ed25519 witness public key (as written by
// openshield-provision witness-keygen).
func loadWitnessPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading witness public key %s: %w", path, err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("witness public key %s is %d bytes, want %d", path, len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// loadAnchor reads a PEM Ed25519 public key, or returns nil when no file is
// given. nil is the honest degraded mode — the CLI states it in the header.
func loadAnchor(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading anchor: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("anchor file %s is not PEM", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing anchor: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("anchor is not an Ed25519 public key")
	}
	return ed, nil
}

// --- minimal flag handling, kept explicit so the command surface is obvious ---

type flags struct {
	dsn, subject, event, anchor, witness string
	since, until                         time.Time
}

func newFlags() *flags {
	dsn := os.Getenv("OPENSHIELD_DSN")
	if dsn == "" {
		dsn = "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"
	}
	return &flags{dsn: dsn}
}

type subcmd struct {
	verb string   // e.g. "export" for `anchor export`
	rest []string // remaining --flag args
}

func parseSubject(cmd string, args []string) subcmd {
	if cmd == "anchor" && len(args) > 0 {
		return subcmd{verb: args[0], rest: args[1:]}
	}
	return subcmd{rest: args}
}

func (f *flags) parse(args []string) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		var v string
		switch a {
		case "--dsn":
			if v, err = next(); err == nil {
				f.dsn = v
			}
		case "--subject":
			if v, err = next(); err == nil {
				f.subject = v
			}
		case "--event":
			if v, err = next(); err == nil {
				f.event = v
			}
		case "--anchor":
			if v, err = next(); err == nil {
				f.anchor = v
			}
		case "--witness":
			if v, err = next(); err == nil {
				f.witness = v
			}
		case "--since":
			if v, err = next(); err == nil {
				f.since, err = time.Parse(time.RFC3339, v)
			}
		case "--until":
			if v, err = next(); err == nil {
				f.until, err = time.Parse(time.RFC3339, v)
			}
		default:
			return fmt.Errorf("unknown flag %q", a)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
