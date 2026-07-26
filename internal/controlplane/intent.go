package controlplane

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// Response-Intent publication (SOAR-7, ADR-12 Tier-2).
//
// The shape mirrors PublishRisk deliberately: the control plane signs a small typed message, the consumer
// verifies it and stores it, and the consumer's LOCAL policy decides what it means. The server publishes
// DATA; it never commands (T2/D14). An open command channel would let a compromised control plane express
// "run this", which is exactly what the closed vocabularies exist to make unexpressible.
//
// IntentVersion is what this build PRODUCES for intents. It is core.WireVersion rather than its own
// literal: two packages already spelled the CONSUMER side of this rule separately, and a producer with a
// third copy is how a publisher and its consumers come to disagree about what "version 1" means.
//
// Bump it only for a change a consumer
// must understand; an unrecognized version is REJECTED rather than partially applied.
const IntentVersion = core.WireVersion

// DefaultIntentTTL bounds an intent. A contain with no expiry is a permanent quarantine nobody remembers
// issuing, so there is no "no expiry" option.
const DefaultIntentTTL = time.Hour

var (
	// ErrIntentUnsigned means no signing key is configured. Publishing unsigned would create a window in
	// which a forging publisher is indistinguishable from the control plane — and containment is a far more
	// attractive forgery target than a risk score.
	ErrIntentUnsigned = errors.New("controlplane: refusing to publish an unsigned response intent")
	// ErrIntentNotApproved means a high-impact verb has no approved four-eyes approval for THIS intent.
	ErrIntentNotApproved = errors.New("controlplane: this intent requires an approved four-eyes approval")
	// ErrBlastRadius means the intent targets more subjects than the configured ceiling.
	ErrBlastRadius = errors.New("controlplane: intent exceeds the configured blast-radius ceiling")
	// ErrIntentVerb means the verb is outside the closed vocabulary.
	ErrIntentVerb = errors.New("controlplane: not a response-intent verb")
)

// SetIntentSigner installs the control-plane key that signs published intents.
func (s *Server) SetIntentSigner(priv ed25519.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.intentSigner = priv
}

// SetIntentBlastRadius sets the maximum number of subjects a single publication run may target.
//
// The failure that matters is not one wrong containment but a FLEET-WIDE one — an operator error or a
// compromised control plane reaching every device at once. The ceiling is checked where the count is known
// (here), because a consumer cannot know how many others received the same intent.
func (s *Server) SetIntentBlastRadius(max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.intentBlastRadius = max
}

// HighImpactVerb reports whether a verb needs a four-eyes approval before publication.
func HighImpactVerb(v corev1.IntentVerb) bool {
	return v == corev1.IntentVerb_INTENT_VERB_CONTAIN || v == corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST
}

// PublishIntents publishes one intent per subject, gated.
//
// Gating order matters: the blast radius is checked FIRST (before any approval lookup or publication), so
// an over-broad request is refused as a whole rather than partially enacted across the first N subjects.
func (s *Server) PublishIntents(ctx context.Context, verb corev1.IntentVerb, subjects []string,
	reason string, ttl time.Duration) ([]string, error) {
	if verb == corev1.IntentVerb_INTENT_VERB_UNSPECIFIED {
		return nil, fmt.Errorf("%w: %v", ErrIntentVerb, verb)
	}
	if _, ok := corev1.IntentVerb_name[int32(verb)]; !ok {
		return nil, fmt.Errorf("%w: %d", ErrIntentVerb, int32(verb))
	}
	s.mu.Lock()
	conn, signer, ceiling := s.conn, s.intentSigner, s.intentBlastRadius
	s.mu.Unlock()

	if ceiling > 0 && len(subjects) > ceiling {
		return nil, fmt.Errorf("%w: %d subjects exceeds the ceiling of %d", ErrBlastRadius, len(subjects), ceiling)
	}
	if len(signer) == 0 {
		return nil, ErrIntentUnsigned
	}
	if ttl <= 0 {
		ttl = DefaultIntentTTL
	}

	now := s.now()
	var published []string
	for _, subject := range subjects {
		id := intentID(subject, verb, now)
		// A high-impact verb needs an approval bound to THIS intent id, so approval to contain host A can
		// never authorize containing host B (SOAR-3's (kind, id) shape exists for exactly this).
		if HighImpactVerb(verb) {
			a, err := s.ApprovalFor(ctx, ApprovalSubjectResponseIntent, id)
			if err != nil || a.State != ApprovalApproved {
				return published, fmt.Errorf("%w: intent %s (%v)", ErrIntentNotApproved, id, err)
			}
		}
		intent := &corev1.ResponseIntent{
			IntentId: id, Verb: verb, Subject: subject, Version: IntentVersion,
			IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(ttl)), Reason: reason,
		}
		payload, err := proto.Marshal(intent)
		if err != nil {
			return published, err
		}
		signed, err := proto.Marshal(&corev1.SignedUpdate{Payload: payload, Signature: ed25519.Sign(signer, payload)})
		if err != nil {
			return published, err
		}
		if conn == nil {
			// No transport: the intent is gated and signed but nothing carries it. Reported rather than
			// silently treated as delivered.
			return published, errors.New("controlplane: no broker connection to publish the intent")
		}
		if err := conn.Publish(natsx.SubjectIntent, signed); err != nil {
			fmt.Fprintf(os.Stderr, "openshield-server: publishing response intent failed: %v\n", err)
			return published, err
		}
		published = append(published, id)
	}
	return published, nil
}

// RequestIntentApproval opens the four-eyes request for an intent the operator intends to publish, so the
// approval is bound to the same id PublishIntents will look up.
func (s *Server) RequestIntentApproval(ctx context.Context, verb corev1.IntentVerb, subject, requester, reason string,
	at time.Time) (intentID string, approvalID int64, err error) {
	id := intentIDFor(subject, verb, at)
	aid, err := s.RequestApproval(ctx, ApprovalSubjectResponseIntent, id, requester, reason, DefaultApprovalTTL)
	return id, aid, err
}

// intentID derives the id an approval binds to. It is deterministic in (subject, verb, minute) so an
// operator can request approval and then publish without threading an id through a UI that does not exist
// yet; the minute granularity keeps a stale approval from authorizing a much later publication.
func intentID(subject string, verb corev1.IntentVerb, at time.Time) string {
	return intentIDFor(subject, verb, at)
}

func intentIDFor(subject string, verb corev1.IntentVerb, at time.Time) string {
	return verb.String() + ":" + subject + ":" + strconv.FormatInt(at.UTC().Unix()/60, 10)
}
