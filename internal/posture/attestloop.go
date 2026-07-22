package posture

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/attest"
	"github.com/lucianoengel/openshield/internal/retain"
)

// AttestLoop runs continuous device attestation: it attests once immediately,
// then re-attests every interval until ctx is cancelled. Zero Trust is continuous
// verification — a device that drifts after login must lose its trusted status, so
// the endpoint keeps proving its current state rather than attesting once.
//
// A failed attempt is logged and skipped, never fatal: the device is simply
// unattested until a later cycle succeeds, which fails closed at the gate (D85) —
// the safe direction. A non-positive interval attests once and does not loop
// (retain.Loop's guard).
func AttestLoop(ctx context.Context, conn *nats.Conn, tpm *attest.TPM, ak *attest.AK, subject string, pcrs []int, interval time.Duration, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	attempt := func(context.Context) {
		if err := Attest(conn, tpm, ak, subject, pcrs); err != nil {
			log.Warn("posture: re-attestation failed", slog.String("subject", subject), slog.Any("err", err))
		}
	}
	attempt(ctx)                        // attest promptly, not one interval late
	retain.Loop(ctx, interval, attempt) // then re-attest continuously
}
