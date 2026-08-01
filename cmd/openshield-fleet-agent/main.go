// Command openshield-fleet-agent is the fleet-facing half of an agent, for the
// fleet simulation (Direction 1). It generates a per-agent identity, enrols over
// HTTP (D51), then publishes SIGNED telemetry and heartbeats (D50/D42) on an
// interval — exercising identity → enroll → verified telemetry → liveness.
//
// It does NOT classify files or run the pipeline (that is the engine); it exists
// to demonstrate the fleet CONTROL path across real containers.
package main

import (
	"context"
	"fmt"
	"github.com/lucianoengel/openshield/internal/config"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/transport/tlsconf"
	"google.golang.org/protobuf/types/known/timestamppb"

	"crypto/ed25519"
	"strings"

	"github.com/lucianoengel/openshield/internal/attest"

	enrollpkg "github.com/lucianoengel/openshield/internal/agent/enroll"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/debpkg"
	"github.com/lucianoengel/openshield/internal/posture"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"github.com/lucianoengel/openshield/internal/transport/queue"
)

func main() {
	// PLAT-5 follow-up: validate every declared field before anything else. BOOTSTRAP-only, and here for a
	// CONSISTENCY reason as much as a capability one: D269 built a signed fleet-control channel on the
	// premise that endpoints do NOT read the configuration store, and making these dynamic would leave two
	// disagreeing answers to "how does an endpoint learn something fleet-wide".
	cfg := config.New(config.FleetAgentFields, config.EnvSource{})
	if len(os.Args) > 1 && os.Args[1] == "config" {
		cfg.WriteEffective(os.Stdout)
		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "\n%v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "openshield-fleet-agent: %v\n", err)
		os.Exit(1)
	}

	agentID := env("OPENSHIELD_AGENT_ID", "fleet-agent")
	enrollURL := env("OPENSHIELD_ENROLL_URL", "http://127.0.0.1:8080/enroll")
	token := os.Getenv("OPENSHIELD_ENROLL_TOKEN")
	natsURL := env("OPENSHIELD_NATS_URL", "nats://127.0.0.1:4222")
	interval := envDuration("OPENSHIELD_HEARTBEAT", 2*time.Second)
	// The pseudonymous subject this agent's activity is attributed to (D23), and
	// how many events it emits per tick — a high burst makes an agent a peer-UEBA
	// OUTLIER relative to the fleet (D54).
	subject := env("OPENSHIELD_SUBJECT", agentID)
	// Device posture is keyed by the CANONICAL pseudonym of the enrolled agent
	// identity (ADR-6/IDENT-1), NOT the raw agentID or OPENSHIELD_SUBJECT. The access
	// proxy resolves posture under pseudonym(cert-CN) and the roster verifies under
	// the same derivation; keying the publish side identically is what makes the
	// posture chain actually match in production. OPENSHIELD_SUBJECT still only shapes
	// this agent's own event attribution (above), never its posture key.
	postureSubject := pseudonym.Of(agentID)
	burst := envInt("OPENSHIELD_BURST", 1)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Mutual TLS on the agent-facing channels (D55), OFF unless configured. A
	// partial/unreadable config fails loudly, never silently to plaintext.
	tlsConf, err := tlsconf.LoadFromEnv()
	if err != nil {
		fatal("TLS configuration: %v", err)
	}
	httpClient := http.DefaultClient
	// RETRY FOREVER. Without this the agent ran on nats.go's defaults — 60 attempts at 2s, then the
	// connection closes for good and this process spools telemetry to a disk queue it will never drain,
	// until the queue hits its ceiling and starts dropping the OLDEST records. See
	// natsx.ResilienceOptions; measured, a 150-second outage was permanent.
	natsOpts := natsx.ResilienceOptions(func(msg string) {
		fmt.Fprintf(os.Stderr, "fleet-agent %s: nats: %s\n", agentID, msg)
	})
	if tlsConf != nil {
		httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf.ClientConfig()}}
		natsOpts = append(natsOpts, nats.Secure(tlsConf.ClientConfig()))
		fmt.Fprintf(os.Stderr, "fleet-agent %s: mutual TLS enabled\n", agentID)
	}

	// THE IDENTITY IS PERSISTED WHEN CONFIGURED, and enrollment is SKIPPED for one that already exists
	// (D318). Before this, the agent could not survive a restart: it generated a new keypair each boot,
	// tokens are single-use, and SEC-2 rightly refuses to replace an enrolled agent's key — so a reboot
	// produced `enroll status 401` and the process exited, taking the endpoint out of the fleet until an
	// operator revoked and re-issued. Each of those three behaviours is correct alone.
	id, created, err := identity.LoadOrCreate(os.Getenv("OPENSHIELD_IDENTITY_FILE"), agentID)
	if err != nil {
		fatal("identity: %v", err)
	}
	if created {
		if err := enrollpkg.Enroll(ctx, httpClient, enrollURL, agentID, token, id); err != nil {
			fatal("enroll: %v", err)
		}
		fmt.Fprintf(os.Stderr, "fleet-agent %s enrolled\n", agentID)
	} else {
		// Announced, because "did not enrol" is otherwise indistinguishable from "silently skipped the
		// trust bootstrap" — and that distinction is the whole of D283.
		fmt.Fprintf(os.Stderr, "fleet-agent %s enrolled (reusing its persisted identity; no token "+
			"needed)\n", agentID)
	}

	conn, err := nats.Connect(natsURL, natsOpts...)
	if err != nil {
		fatal("nats: %v", err)
	}
	defer conn.Close()
	// Persist the telemetry sequence so a restart resumes forward-monotonically
	// instead of resetting to 0 and being rejected as a replay (D66). In-memory
	// when OPENSHIELD_SEQ_FILE is unset.
	var pub *natsx.SignedPublisher
	if seqFile := os.Getenv("OPENSHIELD_SEQ_FILE"); seqFile != "" {
		pub, err = natsx.NewSignedPublisherWithSeq(agentID, id, conn, natsx.NewFileSeqStore(seqFile))
		if err != nil {
			fatal("sequence store: %v", err)
		}
	} else {
		pub = natsx.NewSignedPublisher(agentID, id, conn)
	}

	// Durable ingest (PLAT-2, R34-4): publish into the JetStream telemetry stream so a
	// message survives a control-plane restart and is redelivered until ACKed — the "durable,
	// no loss" claim is only real when the PRODUCER is on JetStream. Gated on
	// OPENSHIELD_JETSTREAM so a deployment without a JetStream-enabled broker keeps the
	// core-NATS path; a spool (below) still covers a broker outage in both modes.
	if err := natsx.EnableDurableIfDefault(pub); err != nil {
		fatal("%v", err)
	}
	if natsx.JetStreamEnabled() {
		fmt.Fprintf(os.Stderr, "fleet-agent %s: durable JetStream ingest enabled (default)\n", agentID)
	} else {
		fmt.Fprintf(os.Stderr, "fleet-agent %s: OPENSHIELD_JETSTREAM=0 — core NATS, AT-MOST-ONCE ingest\n", agentID)
	}

	// Durable offline queue (D40/D67): spool signed telemetry when the control
	// plane is unreachable and re-send it on reconnect, so an outage causes a gap,
	// not silent loss (D1). An overflow eviction is logged LOUDLY — a drop that is
	// not recorded is the silent loss this exists to prevent (D31).
	if qdir := os.Getenv("OPENSHIELD_QUEUE_DIR"); qdir != "" {
		max := envInt("OPENSHIELD_QUEUE_MAX", 10000)
		q, qerr := queue.Open(qdir, max, func(seq uint64) {
			fmt.Fprintf(os.Stderr, "fleet-agent %s: QUEUE OVERFLOW — dropped spooled record seq=%d (ceiling %d)\n", agentID, seq, max)
		})
		if qerr != nil {
			fatal("offline queue: %v", qerr)
		}
		pub.SetSpool(q)
	}

	// HON-4: opt-in device-posture reporting. When OPENSHIELD_POSTURE_SIGNING_KEY is set, the
	// agent detects its device posture and publishes it SIGNED so the gateway can verify it
	// (SEC-1) — the producer that finally gives the D85 tamper-lockout real data. It publishes
	// under postureSubject = the canonical pseudonym of this agent's identity (ADR-6), the same
	// key the gateway roster verifies under and the proxy looks up — a posture update is bound to
	// the reporting agent AND actually found for it.
	var postureKey ed25519.PrivateKey
	if kp := os.Getenv("OPENSHIELD_POSTURE_SIGNING_KEY"); kp != "" {
		key, err := os.ReadFile(kp)
		if err != nil || len(key) != ed25519.PrivateKeySize {
			fatal("posture signing key: %v (want a %d-byte ed25519 key)", err, ed25519.PrivateKeySize)
		}
		postureKey = ed25519.PrivateKey(key)
		fmt.Fprintf(os.Stderr, "fleet-agent %s: signed device-posture reporting enabled (HON-4)\n", agentID)
	}

	// ZT-1 continuous hardware attestation: when a TPM and a PCR set are configured,
	// the agent re-attests on an interval so the gateway's Attested signal tracks this device's
	// current state (a drift drops it within a cycle). The AK must be enrolled at the gateway under
	// postureSubject (the canonical pseudonym) — by self-enrollment here, or by an operator's
	// `openshield-provision attest-capture` file.
	if pcrs := parsePCRs(os.Getenv("OPENSHIELD_ATTEST_PCRS")); len(pcrs) > 0 {
		// IN A GOROUTINE, because this whole block used to run on the agent's MAIN PATH and could
		// BLOCK THERE FOREVER (D314). The comment above it said "attestation never blocks the agent",
		// and the code did the opposite: a TPM that accepts a connection and then does not answer —
		// which is exactly what an un-started software TPM does — wedged the agent before its ticker
		// loop ever started. No heartbeat, no telemetry, no posture, and NO LOG LINE saying why,
		// because every message in this block comes after the call that hangs.
		//
		// That is the worst shape a dependency failure can take: enabling attestation silently
		// disabled everything else the agent does, and from the control plane the machine looked
		// simply absent. Off the main path, a TPM that never answers costs exactly the feature that
		// needs it.
		go setUpAttestation(ctx, conn, agentID, postureSubject, pcrs)
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Drain anything spooled during an outage, in order (best-effort).
			if n, ferr := pub.Flush(); ferr != nil {
				fmt.Fprintf(os.Stderr, "fleet-agent %s: flush stopped after %d (still unreachable?): %v\n", agentID, n, ferr)
			}
			_ = pub.PublishHeartbeat(ctx, &corev1.Heartbeat{AgentId: agentID, ObservedAt: timestamppb.Now()})
			if postureKey != nil {
				rep := posture.Detect()
				// PLAT-6 inc 3: answer "are my binaries the published ones" as part of posture, so it
				// becomes a fleet-wide fact and an access decision rather than a log line on the host
				// that was compromised. Re-checked on every report rather than cached at startup: a
				// binary can be replaced while the agent runs, and a cached answer would keep vouching
				// for it.
				rep.Binaries = binaryIntegrity()
				if err := posture.Publish(conn, postureSubject, rep, postureKey); err != nil {
					fmt.Fprintf(os.Stderr, "fleet-agent %s: posture publish failed: %v\n", agentID, err)
				}
			}
			for i := 0; i < burst; i++ {
				_ = pub.PublishEvent(ctx, &corev1.Event{EventId: agentID + "-ev", AgentId: agentID, ConnectorId: "fleet-sim",
					Kind:    corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
					Subject: &corev1.Subject{PseudonymousId: subject}})
			}
		}
	}
}

// parsePCRs parses a comma-separated PCR list ("16,23") into indices. An empty or absent value disables
// attestation; a malformed entry is skipped but SAID OUT LOUD.
//
// The warning is the fix, and the divergence it covers is worth naming. openshield-provision's
// parsePCRList REFUSES a malformed index outright, on the stated grounds that an empty baseline "attests
// to nothing". This one skips, which is right for a simulation agent that should keep running — but
// skipping SILENTLY meant `OPENSHIELD_ATTEST_PCRS=0,seven` enrolled a baseline over PCR 0 alone while the
// operator had asked for two. Downstream validation cannot catch that: [0] is a perfectly valid non-empty
// baseline. The result is an agent attesting to less than was asked, with nothing to indicate it (D31 — a
// gap must never be silent).
func parsePCRs(s string) []int {
	var pcrs []int
	var skipped []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			skipped = append(skipped, f)
			continue
		}
		pcrs = append(pcrs, n)
	}
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "fleet-agent: OPENSHIELD_ATTEST_PCRS %q — ignoring %d unparseable entry/ies "+
			"(%s); attesting over %v only. A typo here NARROWS the baseline silently, which is why this "+
			"says so.\n", s, len(skipped), strings.Join(skipped, ", "), pcrs)
	}
	return pcrs
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "fleet-agent: "+f+"\n", a...)
	os.Exit(1)
}

// selfEnroll runs the network enrollment handshake, creating the EK it needs and releasing it after.
//
// THE EK IS FLUSHED, and that is not tidiness. A TPM has a small fixed number of object slots; leaving
// the endorsement key loaded after enrollment consumes one for the life of the process, and the next
// component to need a slot — the AK on a restart, another application's key — fails with a TPM
// out-of-memory error that names nothing about this program. `FlushEK` existed for this and had no
// caller, which is consistent: nothing called the enrollment path either.
func selfEnroll(conn *nats.Conn, tpm *attest.TPM, ak *attest.AK, subject string, pcrs []int) error {
	ek, err := tpm.CreateEK()
	if err != nil {
		return fmt.Errorf("creating the endorsement key: %w", err)
	}
	defer func() { _ = tpm.FlushEK(ek) }()
	// The operator's PRE-AUTHORIZATION token, when the deployment issues them (D317). Empty is correct
	// and common: a gateway without OPENSHIELD_ENROLL_PREAUTH_TOKENS ignores the field, so one agent
	// shape serves both. Until D317 nothing could send one at all, which meant a gateway that turned
	// the guard ON could not be enrolled by any shipped client — the control did not make enrollment
	// stricter, it made it impossible.
	return posture.EnrollWithToken(conn, tpm, ek, ak, subject, pcrs,
		os.Getenv("OPENSHIELD_ENROLL_PREAUTH_TOKEN"))
}

// setUpAttestation opens the TPM, creates the AK, optionally self-enrolls, and starts the attest loop.
//
// EVERY FAILURE IS LOGGED AND NON-FATAL. Attestation is a signal the gateway consumes, not a
// precondition for the agent existing; a device with a broken TPM should still report heartbeats and
// telemetry, and be visible as a device that cannot attest — which is a much more useful thing for an
// operator to see than a machine that has vanished.
func setUpAttestation(ctx context.Context, conn *nats.Conn, agentID, subject string, pcrs []int) {
	tpm, err := attest.Open(os.Getenv("OPENSHIELD_TPM_ADDR"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "fleet-agent %s: attestation disabled — open TPM: %v\n", agentID, err)
		return
	}
	// TPM2_STARTUP, which was missing entirely (D314) and is why nothing here could ever work against a
	// software TPM. A hardware TPM is started by the platform firmware before any userspace runs, so
	// omitting it looked correct on the only device anyone had tried; a swtpm is started by whoever
	// connects to it, and until then it answers no command — it does not REFUSE them, it does not
	// answer, so the agent hung.
	//
	// AN ERROR HERE IS NOT FATAL, because the overwhelmingly common case is the good one: a
	// firmware-started TPM answers TPM_RC_INITIALIZE ("already started"), and treating "it was already
	// ready" as a failure would disable attestation on every real machine to satisfy the emulator.
	if err := tpm.Startup(); err != nil {
		fmt.Fprintf(os.Stderr, "fleet-agent %s: TPM startup returned %v (expected on a "+
			"firmware-started TPM, which is already running — continuing)\n", agentID, err)
	}
	ak, err := tpm.CreateAK()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fleet-agent %s: attestation disabled — create AK: %v\n", agentID, err)
		_ = tpm.Close()
		return
	}

	// SELF-ENROLL FIRST (D314), when the operator asks for it.
	//
	// The gateway has SERVED the enrollment protocol since D184 — credential activation, pre-auth
	// tokens, EK-certificate anchoring, all built and unit-tested — and NO SHIPPED BINARY EVER SPOKE
	// IT. `posture.Enroll` had no caller anywhere in the tree. So the automated half of ZT-1 could not
	// happen in a deployment: the only way to populate the verifier was an operator-written JSON file,
	// and the function that WRITES that file (`attest.MarshalEnrollments`) had no caller either.
	//
	// The consequence is worse than an inert feature, because the verifier FAILS CLOSED by design
	// (D85/D186): an empty verifier means every device is unattested, so an operator who turned
	// attestation on and wrote a policy requiring it got a deployment that refused everything, with
	// the gateway logging that enrollment was available.
	//
	// It is OPT-IN because self-enrollment is a trust decision: a device asserting its own identity to
	// the control plane is exactly what pre-auth tokens and EK anchoring exist to constrain, and
	// enabling it by default would hand that decision to a default.
	if os.Getenv("OPENSHIELD_ATTEST_SELF_ENROLL") != "" {
		if err := selfEnroll(conn, tpm, ak, subject, pcrs); err != nil {
			// NOT fatal, and not silent. A gateway that already holds this device in an enrollment file
			// will REJECT a re-enrollment, and that is a correct refusal rather than a reason to stop.
			// Attestation then proceeds and either works — because the device was already enrolled — or
			// does not, visibly.
			fmt.Fprintf(os.Stderr, "fleet-agent %s: self-enrollment did not complete: %v\n", agentID, err)
		} else {
			fmt.Fprintf(os.Stderr, "fleet-agent %s: ZT-1 self-enrolled with the gateway (AK proven "+
				"TPM-resident by credential activation)\n", agentID)
		}
	}

	interval := envDuration("OPENSHIELD_ATTEST_INTERVAL", 5*time.Minute)
	fmt.Fprintf(os.Stderr, "fleet-agent %s: ZT-1 continuous attestation enabled (PCRs %v, every %s)\n",
		agentID, pcrs, interval)
	posture.AttestLoop(ctx, conn, tpm, ak, subject, pcrs, interval, nil)
}

// binaryIntegrity re-hashes this host's installed binaries against the signed release manifest the
// package carried.
//
// UNCHECKED IS THE HONEST ANSWER when no key is configured, when there is no manifest (a source install),
// or when the check itself could not run. None of those mean the binaries are wrong, and none of them
// mean they are right — and core.BinariesUnchecked is the zero value precisely so a policy requiring
// VERIFIED fails closed on all of them.
//
// SELF-REPORTED, with the trust that implies: root here can report anything. What it costs an attacker is
// the signing key, which is not on this machine, so tampering without it shows up — and it shows up at
// the GATEWAY, which the compromised endpoint does not control.
func binaryIntegrity() core.BinaryIntegrity {
	keyPath := os.Getenv("OPENSHIELD_RELEASE_PUBKEY")
	if keyPath == "" {
		return core.BinariesUnchecked
	}
	key, err := os.ReadFile(keyPath)
	if err != nil || len(key) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "fleet-agent: release public key unusable (%v) — reporting binary "+
			"integrity as UNCHECKED rather than guessing\n", err)
		return core.BinariesUnchecked
	}
	rep, err := debpkg.VerifyInstalled(envOr("OPENSHIELD_INSTALL_PREFIX", "/"), ed25519.PublicKey(key))
	if err != nil {
		fmt.Fprintf(os.Stderr, "fleet-agent: binary verification could not run (%v) — reporting "+
			"UNCHECKED\n", err)
		return core.BinariesUnchecked
	}
	if !rep.OK() {
		fmt.Fprintf(os.Stderr, "fleet-agent: THIS INSTALLATION DOES NOT MATCH ITS RELEASE: %s\n",
			rep.Error())
		return core.BinariesMismatch
	}
	return core.BinariesVerified
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
