package controlplane

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// Publishing fleet-wide operational control (PLAT-9).
//
// This is the most consequential message the control plane can send: one accepted DISABLE turns the
// product off across every consumer. It is therefore gated harder than an intent, not the same:
//
//   - a DISABLE requires an APPROVED four-eyes approval bound to the control id — always, with no
//     high-impact/low-impact split, because there is no low-impact way to disable a security product;
//   - it must be SIGNED (an unsigned fleet disable is a forgery target with no equal here);
//   - it carries a MONOTONIC SEQUENCE so a captured message cannot be replayed, and a MANDATORY TTL so a
//     captured or forgotten one cannot last.
//
// ApprovalSubjectFleetControl keys the approval, so approval to disable enforcement once can never
// authorize a later disable — the same (kind, id) discipline SOAR-3 exists for.
const ApprovalSubjectFleetControl = "fleet-control"

// DefaultFleetControlTTL bounds how long a disable stands before consumers treat it as absent. Short on
// purpose: re-issuing is cheap, and a product that is off and nobody remembers turning off is not.
const DefaultFleetControlTTL = 4 * time.Hour

var (
	// ErrFleetVerb means the verb is outside the closed vocabulary.
	ErrFleetVerb = errors.New("controlplane: not a fleet-control verb")
	// ErrFleetUnsigned means no signer is configured. Refusing to publish unsigned is the point: a
	// consumer would reject it anyway, and an unsigned path that "works" is one someone will rely on.
	ErrFleetUnsigned = errors.New("controlplane: refusing to publish an unsigned fleet control")
	// ErrFleetNotApproved means a DISABLE has no approved four-eyes approval for this control id.
	ErrFleetNotApproved = errors.New("controlplane: a fleet-wide enforcement disable requires an approved four-eyes approval")
)

// FleetControlID is the id an approval must be bound to before the matching control can be published.
// Deterministic from the verb and sequence, so an operator requests approval for exactly the control that
// will be sent, not for "a disable" in the abstract.
func FleetControlID(verb corev1.FleetVerb, sequence uint64) string {
	return fmt.Sprintf("fleet:%s:%d", verb.String(), sequence)
}

// NextFleetSequence returns the next monotonic sequence, derived from what has already been published.
//
// Monotonicity is what makes replay impossible on the consumer, so it must not restart: it is stored
// alongside the other durable configuration state rather than held in memory, where a control-plane
// restart would reset it and re-open the replay window.
func (s *Server) NextFleetSequence(ctx context.Context) (uint64, error) {
	var seq uint64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO config_settings (key, value, revision, updated_at)
		 VALUES ('__fleet_control_sequence', '1', 0, now())
		 ON CONFLICT (key) DO UPDATE SET value = (config_settings.value::bigint + 1)::text, updated_at = now()
		 RETURNING value::bigint`).Scan(&seq)
	return seq, err
}

// PublishFleetControl signs and publishes a fleet-wide control.
//
// The approval is checked BEFORE anything is signed or sent: an unapproved disable must not exist on the
// wire even briefly, because a consumer that received it would already have acted.
func (s *Server) PublishFleetControl(ctx context.Context, verb corev1.FleetVerb, reason string,
	ttl time.Duration) (string, error) {
	seq, err := s.NextFleetSequence(ctx)
	if err != nil {
		return "", err
	}
	return s.PublishFleetControlSeq(ctx, verb, reason, ttl, seq)
}

// PublishFleetControlSeq publishes a control at an ALREADY-ALLOCATED sequence.
//
// It exists because the four-eyes gate is keyed by the control id, and the id is derived from the
// sequence: an operator cannot get approval for an id that does not exist yet, and a function that
// allocates its own sequence on every call can therefore never satisfy its own gate — each attempt asks
// for approval of an id the previous attempt burned. Splitting allocation from publication is what makes
// the approved id and the sent id the same one, which is the property the gate is for.
func (s *Server) PublishFleetControlSeq(ctx context.Context, verb corev1.FleetVerb, reason string,
	ttl time.Duration, seq uint64) (string, error) {
	if _, ok := corev1.FleetVerb_name[int32(verb)]; !ok || verb == corev1.FleetVerb_FLEET_VERB_UNSPECIFIED {
		return "", fmt.Errorf("%w: %v", ErrFleetVerb, verb)
	}
	s.mu.Lock()
	conn, signer := s.conn, s.intentSigner
	s.mu.Unlock()
	if len(signer) == 0 {
		return "", ErrFleetUnsigned
	}
	id := FleetControlID(verb, seq)

	// FOUR-EYES ON DISABLE, ALWAYS. No high-impact/low-impact split as intents have: there is no
	// low-impact way to disable a security product fleet-wide.
	if verb == corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE {
		a, aerr := s.ApprovalFor(ctx, ApprovalSubjectFleetControl, id)
		if aerr != nil || a.State != ApprovalApproved {
			return "", fmt.Errorf("%w: control %s", ErrFleetNotApproved, id)
		}
	}
	if ttl <= 0 {
		ttl = DefaultFleetControlTTL
	}
	now := s.now()
	expires := now.Add(ttl)
	payload, err := proto.Marshal(&corev1.FleetControl{
		ControlId: id, Verb: verb, Version: core.WireVersion, Sequence: seq,
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(expires), Reason: reason,
	})
	if err != nil {
		return "", err
	}

	// CONSOLE-8: RECORD BEFORE SENDING, AND FATALLY.
	//
	// Until this, the issued_at/expires_at/reason above existed only on the wire — an operator who found
	// enforcement suppressed could recover none of them. Three orderings were possible: recording before
	// the approval gate would list disables that were refused; recording after the publish would let a
	// successful publish and a failed write leave the fleet suppressed with nothing saying so. Here, the
	// only failure is a control recorded and not sent — which over-reports suppression, and an operator
	// who investigates finds agent_enforcement showing every agent still enforcing.
	//
	// Unlike recordEnforcementState (best-effort, because a heartbeat's purpose is liveness and must not
	// be lost to a projection failure), this ABORTS the publish. A fleet disable has no competing purpose:
	// refusing to turn the product off because we cannot say that we did is the correct trade.
	if err := s.recordFleetControl(ctx, id, verb, seq, now, expires, reason); err != nil {
		return "", err
	}
	signed, err := proto.Marshal(&corev1.SignedUpdate{Payload: payload, Signature: ed25519.Sign(signer, payload)})
	if err != nil {
		return "", err
	}
	if conn == nil {
		return "", errors.New("controlplane: no transport for fleet control")
	}
	if err := conn.Publish(natsx.SubjectFleetControl, signed); err != nil {
		return "", err
	}
	return id, nil
}

// ParseFleetControlID recovers the verb and sequence from a control id.
//
// The id is the operator's handle — it is what an approval is bound to and what the audit trail names —
// so the operator surface takes an ID rather than a verb-and-number they would have to keep together.
func ParseFleetControlID(id string) (corev1.FleetVerb, uint64, error) {
	parts := strings.Split(id, ":")
	if len(parts) != 3 || parts[0] != "fleet" {
		return corev1.FleetVerb_FLEET_VERB_UNSPECIFIED, 0, fmt.Errorf("controlplane: %q is not a fleet-control id", id)
	}
	v, ok := corev1.FleetVerb_value[parts[1]]
	if !ok || corev1.FleetVerb(v) == corev1.FleetVerb_FLEET_VERB_UNSPECIFIED {
		return corev1.FleetVerb_FLEET_VERB_UNSPECIFIED, 0, fmt.Errorf("%w: %q", ErrFleetVerb, parts[1])
	}
	seq, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return corev1.FleetVerb_FLEET_VERB_UNSPECIFIED, 0, fmt.Errorf("controlplane: bad sequence in %q", id)
	}
	return corev1.FleetVerb(v), seq, nil
}
