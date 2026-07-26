package intent_test

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/intent"
)

// PLAT-9: the endpoint half of the fleet-wide disable.
//
// This is the most attractive forgery target in the system — ONE accepted message turns the product off
// across a fleet — so each test here is a bound on a different attack, and every rejection must leave
// enforcement ON.

type fakeSwitch struct {
	mu      sync.Mutex
	engaged bool
	reason  string
	source  string
}

func (f *fakeSwitch) Engage(reason, source string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.engaged, f.reason, f.source = true, reason, source
}
func (f *fakeSwitch) Disengage(source string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.engaged, f.source = false, source
}
func (f *fakeSwitch) state() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.engaged, f.reason
}

func control(t *testing.T, priv ed25519.PrivateKey, verb corev1.FleetVerb, seq uint64,
	expires time.Time, version uint32) []byte {
	t.Helper()
	payload, err := proto.Marshal(&corev1.FleetControl{
		ControlId: "c1", Verb: verb, Version: version, Sequence: seq,
		IssuedAt: timestamppb.New(time.Now()), ExpiresAt: timestamppb.New(expires),
		Reason: "incident 41",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(&corev1.SignedUpdate{Payload: payload, Signature: ed25519.Sign(priv, payload)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newSub(t *testing.T) (*intent.FleetControlSubscriber, *fakeSwitch, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sw := &fakeSwitch{}
	return intent.NewFleetControlSubscriber(pub, sw), sw, priv
}

// TestASignedDisableStopsEnforcementFleetWide — the feature, and the closure of D265's named gap.
func TestASignedDisableStopsEnforcementFleetWide(t *testing.T) {
	sub, sw, priv := newSub(t)
	future := time.Now().Add(time.Hour)

	if err := sub.Apply(control(t, priv, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, 1, future, 1)); err != nil {
		t.Fatalf("a valid disable was rejected: %v", err)
	}
	engaged, reason := sw.state()
	if !engaged || reason != "incident 41" {
		t.Errorf("switch = (%v, %q), want engaged with the operator's reason", engaged, reason)
	}
	// RESTORE is signed too: a forged one would undo a disable an operator engaged during an incident.
	if err := sub.Apply(control(t, priv, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_RESTORE, 2, future, 1)); err != nil {
		t.Fatal(err)
	}
	if engaged, _ := sw.state(); engaged {
		t.Error("a signed restore did not resume enforcement")
	}
	if sub.AppliedSequence() != 2 || sub.Applied.Load() != 2 {
		t.Errorf("applied seq=%d count=%d, want 2 and 2", sub.AppliedSequence(), sub.Applied.Load())
	}
}

// TestAReplayedDisableIsRefused is the bound that a signature alone cannot provide: a CAPTURED, genuinely
// signed disable verifies perfectly every time it is re-sent.
//
// Mutation: drop the sequence check → the replayed disable re-engages after the operator restored
// enforcement → FAILS.
func TestAReplayedDisableIsRefused(t *testing.T) {
	sub, sw, priv := newSub(t)
	future := time.Now().Add(time.Hour)
	captured := control(t, priv, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, 1, future, 1)

	if err := sub.Apply(captured); err != nil {
		t.Fatal(err)
	}
	// The operator restores enforcement.
	if err := sub.Apply(control(t, priv, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_RESTORE, 2, future, 1)); err != nil {
		t.Fatal(err)
	}
	// The attacker re-sends the message they captured. It is authentic; it must still be refused.
	if err := sub.Apply(captured); err == nil {
		t.Fatal("a REPLAYED disable was applied — a captured, genuinely signed message verifies perfectly " +
			"every time, so the signature alone cannot bound this")
	}
	if engaged, _ := sw.state(); engaged {
		t.Error("the replay re-disabled enforcement after an operator had restored it")
	}
	if sub.Rejected.Load() != 1 {
		t.Errorf("rejected = %d, want 1 — a forged-control flood must be observable", sub.Rejected.Load())
	}
}

// TestEveryOtherRejectionLeavesEnforcementOn — fail toward ENFORCING, like the switch it drives.
//
// Mutations: accept a bad signature; accept an unknown version; accept an expired control. Each → FAILS.
func TestEveryOtherRejectionLeavesEnforcementOn(t *testing.T) {
	future := time.Now().Add(time.Hour)

	t.Run("forged signature", func(t *testing.T) {
		sub, sw, _ := newSub(t)
		_, attacker, _ := ed25519.GenerateKey(nil)
		err := sub.Apply(control(t, attacker, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, 1, future, 1))
		if err == nil {
			t.Fatal("a control signed by someone else disabled the product")
		}
		if engaged, _ := sw.state(); engaged {
			t.Error("enforcement was disabled by an unverifiable control")
		}
	})
	t.Run("unknown version", func(t *testing.T) {
		sub, sw, priv := newSub(t)
		err := sub.Apply(control(t, priv, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, 1, future, 2))
		if !errors.Is(err, intent.ErrFleetVersion) {
			t.Fatalf("err = %v, want ErrFleetVersion — a message about turning the product off is the "+
				"last one to guess at", err)
		}
		if engaged, _ := sw.state(); engaged {
			t.Error("an unknown-version control disabled enforcement")
		}
	})
	t.Run("expired", func(t *testing.T) {
		sub, sw, priv := newSub(t)
		past := time.Now().Add(-time.Minute)
		if err := sub.Apply(control(t, priv, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, 1, past, 1)); err == nil {
			t.Fatal("an EXPIRED disable was applied — a captured or forgotten one could then last forever")
		}
		if engaged, _ := sw.state(); engaged {
			t.Error("an expired control disabled enforcement")
		}
	})
	t.Run("no expiry at all", func(t *testing.T) {
		sub, sw, priv := newSub(t)
		payload, _ := proto.Marshal(&corev1.FleetControl{
			ControlId: "c", Verb: corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, Version: 1, Sequence: 1})
		raw, _ := proto.Marshal(&corev1.SignedUpdate{Payload: payload, Signature: ed25519.Sign(priv, payload)})
		if err := sub.Apply(raw); err == nil {
			t.Fatal("a disable with NO expiry was applied — that is a product that is off and nobody " +
				"remembers turning off")
		}
		if engaged, _ := sw.state(); engaged {
			t.Error("an unbounded control disabled enforcement")
		}
	})
	t.Run("no key configured", func(t *testing.T) {
		sw := &fakeSwitch{}
		sub := intent.NewFleetControlSubscriber(nil, sw)
		_, priv, _ := ed25519.GenerateKey(nil)
		if err := sub.Apply(control(t, priv, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, 1, future, 1)); err == nil {
			t.Fatal("a consumer with no key accepted a fleet control")
		}
		if engaged, _ := sw.state(); engaged {
			t.Error("enforcement was disabled with no key to verify against")
		}
	})
}
