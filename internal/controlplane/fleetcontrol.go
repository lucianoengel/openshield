package controlplane

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

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
	if _, ok := corev1.FleetVerb_name[int32(verb)]; !ok || verb == corev1.FleetVerb_FLEET_VERB_UNSPECIFIED {
		return "", fmt.Errorf("%w: %v", ErrFleetVerb, verb)
	}
	s.mu.Lock()
	conn, signer := s.conn, s.intentSigner
	s.mu.Unlock()
	if len(signer) == 0 {
		return "", ErrFleetUnsigned
	}
	seq, err := s.NextFleetSequence(ctx)
	if err != nil {
		return "", err
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
	payload, err := proto.Marshal(&corev1.FleetControl{
		ControlId: id, Verb: verb, Version: 1, Sequence: seq,
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(ttl)), Reason: reason,
	})
	if err != nil {
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
