package gateway

import (
	"context"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Projector is the subset of the signed transport the gateway uses to project
// decisions. It is narrower than core.Transport deliberately: the gateway does not
// own the transport's lifecycle (no Close) — the process that built it does. A
// natsx.SignedPublisher satisfies this directly.
type Projector interface {
	PublishEvent(ctx context.Context, e *corev1.Event) error
	PublishDecision(ctx context.Context, d *corev1.Decision) error
}

// SetTelemetry configures an OPTIONAL projection of decisions to the control plane.
// nil (the default) projects nothing — projection is opt-in and additive; the local
// forward-secure ledger stays the system of record (D30).
func (g *Gateway) SetTelemetry(t Projector) { g.telemetry = t }

// projectTelemetry publishes a BOUNDARY-SAFE view of a decision to the control
// plane: a redacted network Event (destination + verdict, no user IP, no URL path)
// plus the Decision (already schema-guarded to carry no content, D14). Best-effort
// — an error is logged, never fatal: the decision is already durably recorded
// locally, and the publisher offline-queues (D67), so a lost telemetry copy
// degrades the fleet VIEW, not the audit trail.
func (g *Gateway) projectTelemetry(ctx context.Context, ev *corev1.Event, dec *corev1.Decision) {
	if g.telemetry == nil {
		return
	}
	if err := g.telemetry.PublishEvent(ctx, redactForTelemetry(ev)); err != nil {
		g.logger.Warn("gateway: telemetry event projection failed (decision still recorded locally)",
			"err", err, "event", ev.GetEventId())
	}
	if err := g.telemetry.PublishDecision(ctx, dec); err != nil {
		g.logger.Warn("gateway: telemetry decision projection failed (decision still recorded locally)",
			"err", err, "decision", dec.GetDecisionId())
	}
}

// redactForTelemetry returns a copy of the Event safe to cross to the control plane.
// A network Event carries the user's IP and the full URL: src_ip/src_port are
// user-identifying (the Event already carries a pseudonymous Subject, D23) and
// http_path (path+query) routinely carries tokens, credentials or search terms —
// content-like (D10/D29). Both are CLEARED; the DESTINATION (dst_ip/port, sni_host),
// method, protocol, direction and flow_id are KEPT so the fleet view knows where the
// flow went and how it was decided. Non-network events pass through unchanged.
func redactForTelemetry(ev *corev1.Event) *corev1.Event {
	clone := proto.Clone(ev).(*corev1.Event)
	if ns := clone.GetNetwork(); ns != nil {
		ns.SrcIp = ""
		ns.SrcPort = 0
		ns.HttpPath = ""
	}
	return clone
}
