package intent

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// Package intent consumes signed Response-Intents (SOAR-7/ADR-12 Tier-2) as verified policy context.
//
// It lives in its own package because BOTH sides consume intents: the network gateway (flows) and the
// endpoint engine (execs, HIPS-3 inc 2b). The endpoint must never import the network layer, so a shared
// consumer cannot live in internal/gateway.
//
// Response-Intent consumption (SOAR-7, ADR-12 Tier-2).
//
// An intent is DATA the LOCAL policy interprets — never an instruction this code executes. Nothing here
// blocks a flow or denies an exec; it verifies, stores, and exposes the current intent so a policy CAN read
// it. A deployment whose policy ignores intents is unaffected, which is a property of the data-not-command
// model (T2/D14), not a gap.
//
// The honest cost of that property: coverage depends on every consumer opting in, so a policy that never
// reads intents silently provides no containment. The alternative is the command channel this design
// exists to refuse.

// IntentStore holds the current verified intent per subject.
type IntentStore struct {
	mu sync.RWMutex
	m  map[string]*corev1.ResponseIntent
}

func NewStore() *IntentStore { return &IntentStore{m: map[string]*corev1.ResponseIntent{}} }

// Set records an intent, replacing any earlier one for the same subject. A superseding intent is the only
// "undo" besides expiry — there is deliberately no recall message to forge.
func (s *IntentStore) Set(in *corev1.ResponseIntent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[in.GetSubject()] = in
}

// Current returns the subject's intent IN EFFECT, or nil. Callers that need the intent ID (to stamp both
// enactments with the same one — XDR-6) use this; Get is the verb-only convenience.
func (s *IntentStore) Current(subject string) *corev1.ResponseIntent {
	s.mu.RLock()
	in, ok := s.m[subject]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	if exp := in.GetExpiresAt(); exp != nil && !exp.AsTime().After(time.Now()) {
		return nil // expired: absent, so a stale containment cannot outlive its TTL
	}
	return in
}

// Get returns the subject's current intent verb, or UNSPECIFIED when there is none IN EFFECT.
//
// Expiry is evaluated HERE, on read: a consumer must not act on a stale containment even if the control
// plane that issued it is gone. A TTL enforced only at the publisher would leave a permanent quarantine
// behind whenever the publisher died.
func (s *IntentStore) Get(subject string) corev1.IntentVerb {
	s.mu.RLock()
	in, ok := s.m[subject]
	s.mu.RUnlock()
	if !ok {
		return corev1.IntentVerb_INTENT_VERB_UNSPECIFIED
	}
	if exp := in.GetExpiresAt(); exp != nil && !exp.AsTime().After(time.Now()) {
		return corev1.IntentVerb_INTENT_VERB_UNSPECIFIED
	}
	return in.GetVerb()
}

// IntentSubscriber verifies and applies published intents.
type IntentSubscriber struct {
	// Key is the control-plane public key. An intent that does not verify against it is NOT from the
	// control plane, and containment is a far more attractive forgery target than a risk score.
	Key   ed25519.PublicKey
	store *IntentStore
	// Rejected counts intents dropped for a bad signature, an unknown version, or a malformed payload —
	// a forged-intent flood must be observable, not silent.
	Rejected atomic.Int64
}

func NewSubscriber(key ed25519.PublicKey, store *IntentStore) *IntentSubscriber {
	return &IntentSubscriber{Key: key, store: store}
}

// ErrIntentVersion means the intent's version is not one this consumer understands. Rejected rather than
// partially applied: applying the parts we recognize from a message we do not fully understand is how a
// consumer ends up enacting something the publisher did not mean.
var ErrIntentVersion = errors.New("intent: unsupported response-intent version")

// Apply verifies and stores one intent.
//
// Rejections are counted HERE rather than in the Subscribe callback: a counter that only increments on one
// entry point lies the moment anything else calls Apply, and this counter's whole job is to make a
// forged-intent flood observable.
func (r *IntentSubscriber) Apply(raw []byte) error {
	err := r.apply(raw)
	if err != nil {
		r.Rejected.Add(1)
	}
	return err
}

func (r *IntentSubscriber) apply(raw []byte) error {
	var signed corev1.SignedUpdate
	if err := proto.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("intent: bad signed intent: %w", err)
	}
	if len(r.Key) == 0 {
		return errors.New("intent: no control-plane key configured; refusing an unverifiable intent")
	}
	if !ed25519.Verify(r.Key, signed.GetPayload(), signed.GetSignature()) {
		return errors.New("intent: response-intent signature does not verify")
	}
	var in corev1.ResponseIntent
	if err := proto.Unmarshal(signed.GetPayload(), &in); err != nil {
		return fmt.Errorf("intent: bad intent payload: %w", err)
	}
	if in.GetVersion() != 1 {
		return fmt.Errorf("%w: %d", ErrIntentVersion, in.GetVersion())
	}
	if in.GetSubject() == "" || in.GetVerb() == corev1.IntentVerb_INTENT_VERB_UNSPECIFIED {
		return errors.New("intent: intent has no subject or verb")
	}
	r.store.Set(&in)
	return nil
}

// Subscribe wires the subscriber; a rejected intent is counted so a forgery flood is observable.
func (r *IntentSubscriber) Subscribe(conn *nats.Conn) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectIntent, func(m *nats.Msg) {
		_ = r.Apply(m.Data) // Apply counts its own rejections
	})
}
