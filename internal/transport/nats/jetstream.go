package nats

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// TelemetryStream is the JetStream stream that durably buffers signed telemetry (PLAT-2/ADR-2). It is
// a DELIVERY BUS, not the system-of-record — the hash-chained ledger is the evidence store (D12), so
// its retention is WorkQueue (a message is dropped once the single control-plane consumer acks) with
// bounded age/size backstops, never treated as evidence.
const TelemetryStream = "OPENSHIELD_TELEMETRY"

// TelemetryDurable names the control plane's durable consumer, so it resumes from its last ack across
// a restart (that is the whole point — a message published while the consumer was down is delivered
// when it returns, not lost).
const TelemetryDurable = "openshield-telemetry"

// JetStreamEnabled reports whether durable JetStream telemetry ingest is in effect. It is ON BY DEFAULT
// (PLAT-2): signed telemetry is delivered over the durable stream with at-least-once, explicit-ack
// semantics, because at-most-once delivery of an attributable detection means missing evidence.
//
// A deployment whose broker has no JetStream opts OUT explicitly with OPENSHIELD_JETSTREAM=0 (or
// false/off); it then uses core NATS, at-most-once, with the agent's offline spool (D40/D67) as the only
// outage durability. An UNRECOGNIZED value stays ENABLED — a typo must not quietly disable the durability
// a deployer believes they have.
//
// ONE function governs the mode for producers AND the control-plane consumer, deliberately: two flags for
// one wire mode is how a publisher ends up writing to a stream nobody consumes, and that failure is silent.
//
// Neither mode is loss-free, and the docs must not say otherwise: a message never published and never
// spooled is gone, and the stream's bounded limits (see EnsureTelemetryStream) mean a long enough consumer
// outage still drops. The stream is a delivery BUS; the hash-chained ledger is the evidence store (D12).
func JetStreamEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OPENSHIELD_JETSTREAM"))) {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

// EnableDurableIfDefault switches a signed publisher to the durable JetStream path when that is the mode
// in effect, and is a no-op when a deployer has opted out.
//
// Every producer MUST call this. Before PLAT-2 only the fleet SIMULATOR called UseJetStream(): the endpoint
// engine and the network gateway built a publisher and left it on core NATS, so "durable ingest" was true
// for simulated traffic and false for every real detection. Funnelling the switch through one helper is
// what makes that omission a single reviewable line — and what lets a test pin it.
//
// An unavailable JetStream is a FATAL error naming the opt-out, never a silent downgrade: falling back to
// core NATS would leave a deployment believing its telemetry is durable while it is at-most-once, which is
// exactly the missing-evidence failure this path exists to remove.
func EnableDurableIfDefault(p *SignedPublisher) error {
	if !JetStreamEnabled() {
		return nil
	}
	if err := p.UseJetStream(); err != nil {
		return fmt.Errorf("durable telemetry ingest (PLAT-2) is the default but JetStream is unavailable: %w"+
			" — enable JetStream on the broker (nats-server -js), or set OPENSHIELD_JETSTREAM=0 to accept "+
			"at-most-once core-NATS delivery", err)
	}
	return nil
}

// EnsureTelemetryStream idempotently creates the durable, file-backed WorkQueue stream over
// SubjectSigned. Safe to call from every process that connects — an already-existing stream is a
// no-op. The backstops bound the unacked backlog so a permanently-down consumer cannot fill the disk.
func EnsureTelemetryStream(js nats.JetStreamContext) error {
	if _, err := js.StreamInfo(TelemetryStream); err == nil {
		return nil // already exists
	} else if !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	_, err := js.AddStream(&nats.StreamConfig{
		Name:      TelemetryStream,
		Subjects:  []string{SubjectSigned},
		Storage:   nats.FileStorage,
		Retention: nats.WorkQueuePolicy,
		MaxAge:    7 * 24 * time.Hour,
		MaxBytes:  1 << 30, // 1 GiB
	})
	// A concurrent creator may win the race between StreamInfo and AddStream; treat "already in use"
	// as success (idempotent).
	if err != nil && errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		return nil
	}
	return err
}
