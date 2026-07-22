package nats

import (
	"errors"
	"os"
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

// JetStreamEnabled reports whether durable JetStream telemetry ingest is turned on
// (OPENSHIELD_JETSTREAM set). Off by default — the publisher and subscriber use core NATS unless it
// is enabled (PLAT-2 lands the durable path env-gated; flipping the default is a follow-on).
func JetStreamEnabled() bool { return os.Getenv("OPENSHIELD_JETSTREAM") != "" }

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
