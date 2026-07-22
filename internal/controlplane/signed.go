package controlplane

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/notify"
)

// handleSigned verifies a signed telemetry envelope against the ENROLLED agent
// key before persisting it. A bad signature, an unknown or revoked agent, or a
// replay is REJECTED and counted — never persisted. A sequence gap (suppression)
// is recorded and the authentic message still stored. Verified rows are
// attributable (D44), unlike the self-asserted legacy path (D41).
// ingestOutcome classifies a signed-telemetry handling result so the durable-ack consumer (PLAT-2)
// can acknowledge correctly: a persisted or terminally-rejected message is ACKed (done), a transient
// failure is NAKed (redelivered, never dropped). The core-NATS path ignores the return (auto-ack,
// unchanged behavior).
type ingestOutcome int

const (
	ingestPersisted ingestOutcome = iota // stored (or a legitimate gap recorded) — ack
	ingestTransient                      // an infra/DB error — nak and redeliver
	ingestPermanent                      // unverifiable/corrupt/already-applied — ack as terminal, counted
)

// isPermanentVerifyError reports whether a VerifySigned error is a TERMINAL rejection (the message is
// not evidence and will never verify) rather than a transient infrastructure error worth retrying.
// A replay (seq already applied) is terminal too — it is idempotent, so redelivering it forever would
// be a failure mode, not durability.
func isPermanentVerifyError(err error) bool {
	return errors.Is(err, ErrUnknownAgent) || errors.Is(err, ErrRevoked) ||
		errors.Is(err, ErrBadSignature) || errors.Is(err, ErrReplay)
}

func (s *Server) handleSigned(ctx context.Context, data []byte) ingestOutcome {
	var env corev1.SignedTelemetry
	if err := proto.Unmarshal(data, &env); err != nil {
		s.DecodeFailures.Add(1)
		return ingestPermanent // corrupt bytes will not decode on redelivery either
	}
	res, err := s.VerifySigned(ctx, env.GetAgentId(), env.GetSequence(), env.GetPayload(), env.GetSignature(), time.Now())
	if err != nil {
		if isPermanentVerifyError(err) {
			// Unverifiable/replayed telemetry is not evidence: rejected, counted, not stored.
			s.RejectedTelemetry.Add(1)
			return ingestPermanent
		}
		// A transient infrastructure error (DB unreachable, etc.) — do NOT drop or miscount as a
		// rejection; retry so the verified message is not lost.
		return ingestTransient
	}
	if res.Gap {
		s.Gaps.Add(1)
	}
	// R34-12: enforce the subject contract at INGEST (server-side), not only in the
	// endpoint's engine.attribute (client-side) — a legacy or rogue agent must not be
	// able to persist a subject-less event straight into fleet_telemetry. A verified
	// but subject-less event is rejected (permanent: the same bytes won't gain a
	// subject on redelivery), counted, and never stored.
	if env.GetKind() == "event" {
		var ev corev1.Event
		if err := proto.Unmarshal(env.GetPayload(), &ev); err != nil || ev.GetSubject().GetPseudonymousId() == "" {
			s.RejectedTelemetry.Add(1)
			return ingestPermanent
		}
	}
	eventID := eventIDFor(env.GetKind(), env.GetPayload())
	if err := s.insert(ctx, env.GetKind(), env.GetAgentId(), eventID, env.GetPayload(), true); err != nil {
		// A persist failure is transient (a full/down database) — count it (observable) and retry.
		s.DecodeFailures.Add(1)
		return ingestTransient
	}

	// Server-side peer-UEBA (D54), only for a VERIFIED event: an unverified
	// message is not evidence and must never move a subject's baseline (D50).
	// Order: Observe THEN evaluate, so the subject's own event is in the baseline
	// it is judged against — matching the endpoint resolver (D53).
	if s.analyzer != nil && env.GetKind() == "event" {
		s.observePeer(ctx, env.GetAgentId(), env.GetPayload())
	}
	return ingestPersisted
}

// observePeer feeds a verified event's pseudonymous subject (D23) to the fleet
// analyzer and records a peer alert when the subject's peer-relative risk crosses
// the threshold — throttled per subject so one outlier does not alert on every
// event (a rising-edge limiter, not a change to the risk signal).
func (s *Server) observePeer(ctx context.Context, agentID string, payload []byte) {
	var e corev1.Event
	if proto.Unmarshal(payload, &e) != nil {
		return
	}
	subject := e.GetSubject().GetPseudonymousId()
	if subject == "" {
		return
	}
	s.analyzer.Observe(subject)
	pc := s.analyzer.ContextFor(subject)
	if pc == nil || !pc.HasRiskScore || pc.RiskScore < s.peerThreshold {
		return
	}
	now := s.now()
	s.peerMu.Lock()
	last, seen := s.peerLastAlert[subject]
	if seen && now.Sub(last) < s.peerCooldown {
		s.peerMu.Unlock()
		return // within the cooldown — throttle the repeat alert
	}
	s.peerLastAlert[subject] = now
	s.peerMu.Unlock()

	if err := s.recordPeerAlert(ctx, subject, pc.RiskScore, pc.Version, agentID, now); err != nil {
		s.DecodeFailures.Add(1)
		return
	}
	s.PeerAlerts.Add(1)
	// Publish the subject's risk to the gateways (D91), best-effort — so continuous
	// verification (D89) decides on real risk. The server publishes DATA; the gateway
	// decides (T2/D14). A publish failure never breaks ingest.
	s.PublishRisk(ctx, subject, pc.RiskScore)
	// Deliver the alert to a human (D83), best-effort — additive to the record it
	// already made. Rides observePeer's existing per-subject cooldown, so no
	// separate throttle is needed.
	s.emit(ctx, notify.Notification{Kind: notify.KindPeerAlert, Subject: subject, RiskScore: pc.RiskScore, At: now})
}

// recordPeerAlert persists a server-side detection to peer_alerts — a DERIVATION,
// deliberately apart from received telemetry (D54); it is not the ledger (D38).
func (s *Server) recordPeerAlert(ctx context.Context, subject string, risk float64, ctxVersion, agentID string, at time.Time) error {
	// SIEM-6b/ADR-10: stamp the first-class lifecycle fields at write — severity from the risk (so it
	// is correct for the recorded alert even if thresholds later change), status open, and a
	// detector-namespaced correlation key. A future cross-domain detector writes the same shape.
	_, err := s.pool.Exec(ctx,
		`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id, detected_at, severity, status, dedup_key)
		 VALUES ($1,$2,$3,$4,$5,$6,'open',$7)`,
		subject, risk, ctxVersion, agentID, at.UTC(), Severity(risk), "peer-ueba:"+subject)
	return err
}

// eventIDFor extracts the event id for indexing from a payload of the given kind.
func eventIDFor(kind string, payload []byte) string {
	switch kind {
	case "event":
		var e corev1.Event
		if proto.Unmarshal(payload, &e) == nil {
			return e.GetEventId()
		}
	case "classification":
		var c corev1.ClassificationSummary
		if proto.Unmarshal(payload, &c) == nil {
			return c.GetEventId()
		}
	case "decision":
		var d corev1.Decision
		if proto.Unmarshal(payload, &d) == nil {
			return d.GetEventId()
		}
	}
	return ""
}
