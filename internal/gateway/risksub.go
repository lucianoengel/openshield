package gateway

import (
	"crypto/ed25519"
	"fmt"
	"sync/atomic"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// RiskSubscriber applies SIGNED risk updates to the store (SEC-1). Risk is published by the
// control plane and signed with its key; the subscriber verifies each update against the
// trusted control-plane public key BEFORE applying it, so anyone who can merely publish to
// the risk subject (any enrolled agent, or anyone past broker mTLS) cannot forge risk for
// any subject — without this, defeating D89 continuous-verification step-up/deny is trivial.
// An update that does not verify is DROPPED and COUNTED, never applied.
type RiskSubscriber struct {
	store      *RiskStore
	trustedPub ed25519.PublicKey
	Rejected   atomic.Int64 // updates dropped for failing verification (observable, SEC-1)
}

// NewRiskSubscriber builds a subscriber that verifies against the control-plane key.
func NewRiskSubscriber(store *RiskStore, trustedPub ed25519.PublicKey) *RiskSubscriber {
	return &RiskSubscriber{store: store, trustedPub: trustedPub}
}

// Apply verifies a signed risk update and records the subject's latest risk. A malformed,
// unsigned, wrong-key, or tampered update is an error — the caller counts it as rejected,
// never a silent no-op (SEC-1). Verification happens BEFORE the inner RiskUpdate is parsed.
func (r *RiskSubscriber) Apply(data []byte) error {
	payload, err := verifySignedUpdate(data, r.trustedPub)
	if err != nil {
		return err
	}
	var ru corev1.RiskUpdate
	if err := proto.Unmarshal(payload, &ru); err != nil {
		return fmt.Errorf("gateway: bad risk update: %w", err)
	}
	if ru.GetSubject() == "" {
		return fmt.Errorf("gateway: risk update has no subject")
	}
	r.store.Set(ru.GetSubject(), ru.GetRiskScore())
	return nil
}

// Subscribe wires the subscriber to the risk subject; an update that fails verification is
// dropped and counted (Rejected), so a forged-risk flood is observable, not silent.
func (r *RiskSubscriber) Subscribe(conn *nats.Conn) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectRisk, func(m *nats.Msg) {
		if err := r.Apply(m.Data); err != nil {
			r.Rejected.Add(1)
		}
	})
}
