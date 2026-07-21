package engine

import (
	"context"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Projector is the subset of the signed transport the engine uses to project real
// detections to the control plane. Narrower than core.Transport (no Close — the
// engine does not own the transport's lifecycle) and defined engine-local so the
// endpoint layer does not depend on the network layer. A natsx.SignedPublisher
// satisfies it directly. Mirrors gateway.Projector (D77/D80).
type Projector interface {
	PublishEvent(ctx context.Context, e *corev1.Event) error
	PublishDecision(ctx context.Context, d *corev1.Decision) error
}

// SetTelemetry configures an OPTIONAL projection of detections to the control plane.
// nil (the default) projects nothing — projection is opt-in and additive; the local
// forward-secure ledger stays the system of record (D30).
func (e *Engine) SetTelemetry(t Projector) { e.telemetry = t }

// projectTelemetry publishes a detection to the control plane so fleet visibility,
// peer-UEBA and the dead-man's-switch operate over REAL endpoint detections, not
// only the simulator (D80). The Event is projected AS-IS: its filesystem path is the
// file's identity (the fleet investigation needs "which file on which endpoint") and
// the Subject is already pseudonymous (D23) — distinct from the gateway, which
// redacts the URL path because a URL path is content-like (D77). The Decision is
// schema-guarded to carry no content (D14).
//
// Best-effort — a publish error is logged, never fatal: the decision is already
// durably recorded in the local ledger (D30) and the publisher offline-queues (D67),
// so a lost telemetry copy degrades the fleet VIEW, not the audit trail.
func (e *Engine) projectTelemetry(ctx context.Context, ev *corev1.Event, dec *corev1.Decision) {
	if e.telemetry == nil {
		return
	}
	if err := e.telemetry.PublishEvent(ctx, ev); err != nil {
		e.logger.Warn("engine: telemetry event projection failed (decision still recorded locally)",
			"err", err, "event", ev.GetEventId())
	}
	if err := e.telemetry.PublishDecision(ctx, dec); err != nil {
		e.logger.Warn("engine: telemetry decision projection failed (decision still recorded locally)",
			"err", err, "decision", dec.GetDecisionId())
	}
}
