package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// PLAT-9: publishing a fleet-wide disable is gated harder than an intent, because there is no low-impact
// way to disable a security product fleet-wide.
//
// Mutation: skip the approval check → an unapproved disable reaches the wire → FAILS.
func TestAFleetDisableRequiresFourEyes(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	url := embeddedNATS(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetIntentSigner(priv)

	// Unapproved: refused, and nothing is signed or sent. An unapproved disable must not exist on the
	// wire even briefly — a consumer that received it would already have acted.
	if _, err := srv.PublishFleetControl(ctx, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE,
		"incident 41", time.Hour); !errors.Is(err, controlplane.ErrFleetNotApproved) {
		t.Fatalf("err = %v, want ErrFleetNotApproved", err)
	}

	// The id an approval must be bound to is DETERMINISTIC from the verb and the next sequence, so an
	// operator approves exactly the control that will be sent — not "a disable" in the abstract.
	seq, err := srv.NextFleetSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := controlplane.FleetControlID(corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE, seq+1)
	aid, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectFleetControl, id,
		"operator:alice", "stop enforcing", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ResolveApproval(ctx, aid, "operator:bob", true); err != nil {
		t.Fatal(err)
	}
	got, err := srv.PublishFleetControl(ctx, corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE,
		"incident 41", time.Hour)
	if err != nil {
		t.Fatalf("an APPROVED disable was refused: %v", err)
	}
	if got != id {
		t.Errorf("published %q, want the approved id %q — an approval must authorize exactly the control "+
			"that is sent", got, id)
	}

	// The sequence is MONOTONIC and survives a restart, because it is stored rather than held in memory:
	// a reset would re-open the replay window on every consumer.
	next, err := srv.NextFleetSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if next <= seq+1 {
		t.Errorf("sequence did not advance past %d (got %d)", seq+1, next)
	}
}

// TestAnUnsignedFleetControlIsRefused — a consumer would reject it anyway, and an unsigned path that
// "works" is one someone will come to rely on.
func TestAnUnsignedFleetControlIsRefused(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	if _, err := srv.PublishFleetControl(context.Background(),
		corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_RESTORE, "", time.Hour); !errors.Is(err, controlplane.ErrFleetUnsigned) {
		t.Errorf("err = %v, want ErrFleetUnsigned", err)
	}
}
