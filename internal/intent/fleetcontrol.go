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

// Fleet-wide operational control (PLAT-9): the endpoint half of "stop enforcing now".
//
// D265's kill switch reaches server-side components through the configuration store. ENDPOINT AGENTS DO
// NOT READ IT, so until this they were disabled only by a local break-glass file — a gap named when the
// switch shipped rather than left for someone to discover.
//
// THIS IS THE MOST ATTRACTIVE FORGERY TARGET IN THE SYSTEM: one accepted message turns the product off
// across a fleet. So it carries three independent bounds, and each answers a different attack:
//
//   - the SIGNATURE answers "who said this" (origin, not authority — a compromised control plane is
//     indistinguishable, which is why publication is separately four-eyes gated);
//   - a MONOTONIC SEQUENCE answers replay: a captured DISABLE cannot be re-sent after an operator
//     restored enforcement, because it is at or below the highest sequence already applied;
//   - MANDATORY EXPIRY answers duration: a captured or forgotten DISABLE cannot last, because a consumer
//     treats an expired control as absent.
//
// And it FAILS TOWARD ENFORCING, like the switch it drives: anything unverifiable, replayed, expired or
// of an unknown version changes nothing at all.

// ErrFleetVersion means the control carries a version this consumer does not understand. Rejected whole
// rather than partially applied — a message about turning the product off is the last one to guess at.
var ErrFleetVersion = errors.New("intent: unknown fleet-control version")

// Applier is what a verified control acts on — core.KillSwitch satisfies it. An interface so this package
// does not import the enforcement path it drives.
type Applier interface {
	Engage(reason, source string)
	Disengage(source string)
}

// FleetControlSubscriber verifies signed fleet controls and applies them.
type FleetControlSubscriber struct {
	// Key is the control-plane public key. A control that does not verify against it is not from the
	// control plane, and this message type disables the product.
	Key ed25519.PublicKey

	mu      sync.Mutex
	applied uint64 // the highest sequence applied — the replay bound
	target  Applier

	// Rejected counts controls dropped for a bad signature, an unknown version, a replay or expiry. A
	// forged-control flood must be observable, not silent.
	Rejected atomic.Int64
	// Applied counts controls that took effect.
	Applied atomic.Int64
}

func NewFleetControlSubscriber(key ed25519.PublicKey, target Applier) *FleetControlSubscriber {
	return &FleetControlSubscriber{Key: key, target: target}
}

// Apply verifies and applies one signed control.
func (f *FleetControlSubscriber) Apply(raw []byte) error {
	err := f.apply(raw)
	if err != nil {
		f.Rejected.Add(1)
	}
	return err
}

func (f *FleetControlSubscriber) apply(raw []byte) error {
	var signed corev1.SignedUpdate
	if err := proto.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("intent: bad signed fleet control: %w", err)
	}
	if len(f.Key) == 0 {
		return errors.New("intent: no control-plane key configured; refusing an unverifiable fleet control")
	}
	if !ed25519.Verify(f.Key, signed.GetPayload(), signed.GetSignature()) {
		return errors.New("intent: fleet-control signature does not verify")
	}
	var c corev1.FleetControl
	if err := proto.Unmarshal(signed.GetPayload(), &c); err != nil {
		return fmt.Errorf("intent: bad fleet-control payload: %w", err)
	}
	if c.GetVersion() != 1 {
		return fmt.Errorf("%w: %d", ErrFleetVersion, c.GetVersion())
	}
	if v := c.GetVerb(); v == corev1.FleetVerb_FLEET_VERB_UNSPECIFIED {
		return errors.New("intent: fleet control carries no verb")
	}
	// EXPIRY, evaluated on arrival AND meaningful: a control with no bound, or a lapsed one, is refused.
	// A disable that cannot lapse is a product that is off and nobody remembers turning off.
	exp := c.GetExpiresAt()
	if exp == nil || !exp.AsTime().After(time.Now()) {
		return errors.New("intent: fleet control is expired or carries no expiry")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	// REPLAY: refuse anything at or below the highest sequence already applied. Without this, an attacker
	// who captured a legitimate DISABLE could re-send it after an operator restored enforcement, and it
	// would verify perfectly every time.
	if c.GetSequence() <= f.applied {
		return fmt.Errorf("intent: fleet control sequence %d is not above the applied %d (replay)",
			c.GetSequence(), f.applied)
	}
	f.applied = c.GetSequence()

	source := "fleet:" + c.GetControlId()
	switch c.GetVerb() {
	case corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE:
		reason := c.GetReason()
		if reason == "" {
			reason = "fleet-wide enforcement disable"
		}
		f.target.Engage(reason, source)
	case corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_RESTORE:
		f.target.Disengage(source)
	}
	f.Applied.Add(1)
	return nil
}

// AppliedSequence is the highest sequence this consumer has applied — the answer to "has this host caught
// up", and the value an operator compares across a fleet mid-disable.
func (f *FleetControlSubscriber) AppliedSequence() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied
}

// Subscribe wires the subscriber; a rejected control is counted so a forgery flood is observable.
func (f *FleetControlSubscriber) Subscribe(conn *nats.Conn) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectFleetControl, func(m *nats.Msg) {
		_ = f.Apply(m.Data) // Apply counts its own rejections
	})
}
