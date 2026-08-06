package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/transport/tlsconf"
)

// The operator surface for the FLEET-WIDE emergency disable (PLAT-9).
//
// A SUBCOMMAND, not an HTTP route, for the D51 reason token issuance is not one: this is the most
// consequential message the control plane can send — one accepted DISABLE turns the product off across
// every consumer — and an endpoint that accepts it is an endpoint that can be made to turn the product
// off. Issuance stays operator-local.
//
// TWO STEPS, and the split is forced by the gate rather than chosen for taste. The four-eyes approval is
// bound to the CONTROL ID, and the id is derived from the sequence, so an operator cannot approve an id
// that does not exist yet. `prepare` allocates the sequence and prints the id to be approved; `publish`
// sends exactly that id. A single-step command that allocated its own sequence could never satisfy its
// own gate: each attempt would ask for approval of an id the previous attempt had already burned.
//
//	openshield-server fleet-control prepare disable|restore [reason]
//	openshield-server fleet-control publish <control-id> [reason] [ttl]
func fleetControl(dsn string, args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage:\n"+
			"  openshield-server fleet-control prepare disable|restore [reason]\n"+
			"  openshield-server fleet-control publish <control-id> [reason] [ttl]")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fleet-control:", err)
		return 1
	}
	defer pool.Close()
	srv := controlplane.New(pool)

	switch args[0] {
	case "prepare":
		verb, ok := fleetVerb(args[1])
		if !ok {
			fmt.Fprintf(os.Stderr, "fleet-control: %q is not a verb (want disable or restore)\n", args[1])
			return 2
		}
		seq, serr := srv.NextFleetSequence(ctx)
		if serr != nil {
			fmt.Fprintln(os.Stderr, "fleet-control:", serr)
			return 1
		}
		id := controlplane.FleetControlID(verb, seq)
		fmt.Println(id)
		if verb == corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE {
			fmt.Fprintf(os.Stderr, "openshield-server: control %s allocated. A DISABLE requires an APPROVED "+
				"four-eyes approval bound to this exact id before it can be published — there is no "+
				"low-impact way to disable a security product fleet-wide.\n", id)
		}
		return 0

	case "publish":
		verb, seq, perr := controlplane.ParseFleetControlID(args[1])
		if perr != nil {
			fmt.Fprintln(os.Stderr, "fleet-control:", perr)
			return 2
		}
		reason := ""
		if len(args) > 2 {
			reason = args[2]
		}
		ttl := controlplane.DefaultFleetControlTTL
		if len(args) > 3 {
			d, derr := time.ParseDuration(args[3])
			if derr != nil {
				fmt.Fprintf(os.Stderr, "fleet-control: %q is not a duration\n", args[3])
				return 2
			}
			ttl = d
		}
		key, kerr := intentSigningKey()
		if kerr != nil {
			fmt.Fprintln(os.Stderr, "fleet-control:", kerr)
			return 1
		}
		if len(key) == 0 {
			fmt.Fprintln(os.Stderr, "fleet-control: OPENSHIELD_RISK_SIGNING_KEY is unset. An unsigned fleet "+
				"control is refused by every consumer, so publishing one would only look like it worked.")
			return 1
		}
		srv.SetIntentSigner(key)

		// MUTUAL TLS TO THE BROKER (D55), which this command did not do — and could not publish without.
		//
		// The long-running server applies these options; this subcommand builds its own Server and never
		// did, so on any deployment following the mutual-TLS posture the product recommends, publishing a
		// fleet-wide disable failed at the handshake with an x509 error. "How do I stop this?" had no
		// answer on precisely the deployments that hardened themselves — the D375 shape again, one
		// command later, and found only by running the CLI against the TLS integration stack.
		//
		// The same loud-or-nothing rule as the server: a partial configuration is an error, never a
		// silent fall-back to plaintext that would fail later and less clearly.
		tlsConf, terr := tlsconf.LoadFromEnv()
		if terr != nil {
			fmt.Fprintln(os.Stderr, "fleet-control: TLS configuration:", terr)
			return 1
		}
		if tlsConf != nil {
			srv.SetNATSOptions(nats.Secure(tlsConf.ClientConfig()))
		}
		natsURL := env("OPENSHIELD_NATS_URL", "nats://127.0.0.1:4222")
		if cerr := srv.Connect(natsURL); cerr != nil {
			fmt.Fprintln(os.Stderr, "fleet-control: connecting to the broker:", cerr)
			return 1
		}
		defer srv.Close()
		id, err := srv.PublishFleetControlSeq(ctx, verb, reason, ttl, seq)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fleet-control:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "openshield-server: published %s (expires in %s). Consumers STOP ENFORCING "+
			"and keep detecting and auditing; the control lapses on its own, because a disable nobody "+
			"remembers turning on is the failure the TTL exists for.\n", id, ttl)
		return 0
	}
	fmt.Fprintf(os.Stderr, "fleet-control: unknown action %q\n", args[0])
	return 2
}

func fleetVerb(s string) (corev1.FleetVerb, bool) {
	switch s {
	case "disable":
		return corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, true
	case "restore":
		return corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_RESTORE, true
	}
	return corev1.FleetVerb_FLEET_VERB_UNSPECIFIED, false
}

// intentSigningKey loads the PRIVATE key that signs intents and fleet controls.
func intentSigningKey() (ed25519.PrivateKey, error) {
	kp := os.Getenv("OPENSHIELD_RISK_SIGNING_KEY")
	if kp == "" {
		return nil, nil
	}
	key, err := os.ReadFile(kp)
	if err != nil {
		return nil, fmt.Errorf("reading the signing key: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key is %d bytes, want %d (raw ed25519 private key)",
			len(key), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(key), nil
}
