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
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/posture"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"github.com/lucianoengel/openshield/internal/transport/queue"
)

func main() {
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
	var natsOpts []nats.Option
	if tlsConf != nil {
		httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf.ClientConfig()}}
		natsOpts = append(natsOpts, nats.Secure(tlsConf.ClientConfig()))
		fmt.Fprintf(os.Stderr, "fleet-agent %s: mutual TLS enabled\n", agentID)
	}

	id, err := identity.Generate(agentID)
	if err != nil {
		fatal("identity: %v", err)
	}
	if err := enrollpkg.Enroll(ctx, httpClient, enrollURL, agentID, token, id); err != nil {
		fatal("enroll: %v", err)
	}
	fmt.Fprintf(os.Stderr, "fleet-agent %s enrolled\n", agentID)

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
	// the agent re-attests on an interval so the gateway's Attested signal tracks
	// this device's current state (a drift drops it within a cycle). Best-effort —
	// a TPM-open failure logs and skips; attestation never blocks the agent. The AK
	// must be enrolled at the gateway under postureSubject (the canonical pseudonym).
	if pcrs := parsePCRs(os.Getenv("OPENSHIELD_ATTEST_PCRS")); len(pcrs) > 0 {
		tpm, terr := attest.Open(os.Getenv("OPENSHIELD_TPM_ADDR"))
		if terr != nil {
			fmt.Fprintf(os.Stderr, "fleet-agent %s: attestation disabled — open TPM: %v\n", agentID, terr)
		} else {
			ak, aerr := tpm.CreateAK()
			if aerr != nil {
				fmt.Fprintf(os.Stderr, "fleet-agent %s: attestation disabled — create AK: %v\n", agentID, aerr)
				_ = tpm.Close()
			} else {
				attInterval := envDuration("OPENSHIELD_ATTEST_INTERVAL", 5*time.Minute)
				go posture.AttestLoop(ctx, conn, tpm, ak, postureSubject, pcrs, attInterval, nil)
				fmt.Fprintf(os.Stderr, "fleet-agent %s: ZT-1 continuous attestation enabled (PCRs %v, every %s)\n", agentID, pcrs, attInterval)
			}
		}
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
				if err := posture.Publish(conn, postureSubject, posture.Detect(), postureKey); err != nil {
					fmt.Fprintf(os.Stderr, "fleet-agent %s: posture publish failed: %v\n", agentID, err)
				}
			}
			for i := 0; i < burst; i++ {
				_ = pub.PublishEvent(ctx, &corev1.Event{EventId: agentID + "-ev", AgentId: agentID,
					Kind:    corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
					Subject: &corev1.Subject{PseudonymousId: subject}})
			}
		}
	}
}

// parsePCRs parses a comma-separated PCR list ("16,23") into indices; malformed or
// empty entries are skipped, an empty/absent value disables attestation.
func parsePCRs(s string) []int {
	var pcrs []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if n, err := strconv.Atoi(f); err == nil {
			pcrs = append(pcrs, n)
		}
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
