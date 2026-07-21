package controlplane

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// handleSigned verifies a signed telemetry envelope against the ENROLLED agent
// key before persisting it. A bad signature, an unknown or revoked agent, or a
// replay is REJECTED and counted — never persisted. A sequence gap (suppression)
// is recorded and the authentic message still stored. Verified rows are
// attributable (D44), unlike the self-asserted legacy path (D41).
func (s *Server) handleSigned(ctx context.Context, data []byte) {
	var env corev1.SignedTelemetry
	if err := proto.Unmarshal(data, &env); err != nil {
		s.DecodeFailures.Add(1)
		return
	}
	res, err := s.VerifySigned(ctx, env.GetAgentId(), env.GetSequence(), env.GetPayload(), env.GetSignature(), time.Now())
	if err != nil {
		// Unverifiable telemetry is not evidence: rejected, counted, not stored.
		s.RejectedTelemetry.Add(1)
		return
	}
	if res.Gap {
		s.Gaps.Add(1)
	}
	eventID := eventIDFor(env.GetKind(), env.GetPayload())
	if err := s.insert(ctx, env.GetKind(), env.GetAgentId(), eventID, env.GetPayload(), true); err != nil {
		s.DecodeFailures.Add(1)
	}
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
