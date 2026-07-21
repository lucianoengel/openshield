// Command openshield-anchor witnesses the audit ledger head and stores an anchor
// (T-019/D38, D64). It is the runnable half of external anchoring: without it,
// AnchorHead never runs and a deployment stays permanently Completeness:
// UNVERIFIED.
//
// It is a WITNESS authority tool, deliberately separate from the read-only
// openshieldctl. It holds ONLY the witness key and opens the ledger SIGNER-LESS
// (it attests to the head, it cannot append) — the whole point of a witness is
// that it is a party the ledger writer cannot impersonate.
//
// CUSTODY IS THE GUARANTEE (T-019): run this from a trust domain the deployer
// does NOT control (a second host, WORM storage, a transparency service). An
// anchor witnessed by a key the deployer holds attests to little. The
// undetectable-loss window is the interval between anchors — the schedule chooses
// the window.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("openshield-anchor", flag.ContinueOnError)
	dsn := fs.String("dsn", env("OPENSHIELD_DSN", "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"), "ledger DSN")
	keyPath := fs.String("witness", os.Getenv("OPENSHIELD_WITNESS_KEY"), "witness private key file (raw Ed25519)")
	interval := fs.Duration("interval", 0, "if >0, anchor repeatedly on this interval; otherwise one-shot")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "openshield-anchor: --witness (or OPENSHIELD_WITNESS_KEY) is required")
		return 2
	}

	witness, err := loadWitness(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "openshield-anchor:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "openshield-anchor: CUSTODY NOTE — this witness attests to the ledger head; "+
		"its guarantee holds only if this key lives in a trust domain the ledger operator does not control (T-019).")

	ctx := context.Background()
	// SIGNER-LESS: the witness cannot hold or use the ledger signer.
	ledger, err := postgres.OpenForVerify(ctx, *dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "openshield-anchor: opening ledger:", err)
		return 1
	}
	defer ledger.Close()

	anchorOnce := func() int {
		a, err := ledger.AnchorHead(ctx, witness)
		if err != nil {
			fmt.Fprintln(os.Stderr, "openshield-anchor: anchoring:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "openshield-anchor: witnessed head at sequence=%d\n", a.Sequence)
		return 0
	}

	if *interval <= 0 {
		return anchorOnce() // one-shot: the natural shape for a systemd timer / cron
	}
	for {
		anchorOnce()
		time.Sleep(*interval)
	}
}

// loadWitness reads a raw Ed25519 private key file and reconstructs the witness.
func loadWitness(path string) (*core.Witness, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading witness key %s: %w", path, err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("witness key %s is %d bytes, want %d (raw Ed25519 private key)", path, len(b), ed25519.PrivateKeySize)
	}
	return core.WitnessFromKey(ed25519.PrivateKey(b))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
