package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/intent"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// TestIntentVerbVocabularyIsClosed mirrors the Action-set guard (D14): the threat is a compromised control
// plane expressing an arbitrary action, so adding a verb must be a deliberate edit here, not a config change.
func TestIntentVerbVocabularyIsClosed(t *testing.T) {
	want := map[string]bool{
		"INTENT_VERB_UNSPECIFIED": true, "INTENT_VERB_ELEVATE_SCRUTINY": true,
		"INTENT_VERB_CONTAIN": true, "INTENT_VERB_REVOKE_TRUST": true,
	}
	vals := corev1.IntentVerb(0).Descriptor().Values()
	if vals.Len() != len(want) {
		t.Fatalf("IntentVerb has %d members, want %d — a new response verb is a one-at-a-time owner "+
			"decision (ADR-12), so update this test deliberately", vals.Len(), len(want))
	}
	for i := 0; i < vals.Len(); i++ {
		if !want[string(vals.Get(i).Name())] {
			t.Errorf("unexpected intent verb %q", vals.Get(i).Name())
		}
	}
	// And the high-impact classification is explicit.
	if !controlplane.HighImpactVerb(corev1.IntentVerb_INTENT_VERB_CONTAIN) ||
		!controlplane.HighImpactVerb(corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST) {
		t.Error("contain/revoke-trust must be high-impact (four-eyes gated)")
	}
	if controlplane.HighImpactVerb(corev1.IntentVerb_INTENT_VERB_ELEVATE_SCRUTINY) {
		t.Error("elevate-scrutiny must not require an approval; gating a low-impact verb trains operators " +
			"to rubber-stamp")
	}
}

// TestUnapprovedHighImpactIntentIsNotPublished is the four-eyes gate on containment.
//
// Mutation: skip the approval lookup → the intent publishes without a second operator → this FAILS.
func TestUnapprovedHighImpactIntentIsNotPublished(t *testing.T) {
	pool := requireDB(t)
	url := embeddedNATS(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)

	_, priv, _ := ed25519.GenerateKey(nil)
	srv.SetIntentSigner(priv)

	// Watch the wire: nothing may appear.
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	seen := make(chan struct{}, 4)
	if _, err := conn.Subscribe(natsx.SubjectIntent, func(*nats.Msg) { seen <- struct{}{} }); err != nil {
		t.Fatal(err)
	}

	_, err = srv.PublishIntents(ctx, corev1.IntentVerb_INTENT_VERB_CONTAIN, []string{"sub_a"}, "burst", time.Hour)
	if !errors.Is(err, controlplane.ErrIntentNotApproved) {
		t.Fatalf("publishing an unapproved CONTAIN err = %v, want ErrIntentNotApproved", err)
	}
	select {
	case <-seen:
		t.Fatal("an unapproved containment intent reached the wire — one operator could contain a host")
	case <-time.After(300 * time.Millisecond):
	}

	// With an approval bound to THIS intent, it publishes.
	now := time.Now()
	intentID, aid, err := srv.RequestIntentApproval(ctx, corev1.IntentVerb_INTENT_VERB_CONTAIN, "sub_a",
		"cert:alice", "burst", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ResolveApproval(ctx, aid, "cert:bob", true); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.PublishIntents(ctx, corev1.IntentVerb_INTENT_VERB_CONTAIN, []string{"sub_a"}, "burst", time.Hour); err != nil {
		t.Fatalf("publishing an APPROVED contain: %v (intent %s)", err, intentID)
	}
	select {
	case <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("an approved containment intent never reached the wire")
	}
}

// TestLowImpactIntentNeedsNoApproval: gating everything trains operators to rubber-stamp.
func TestLowImpactIntentNeedsNoApproval(t *testing.T) {
	pool := requireDB(t)
	url := embeddedNATS(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(100 * time.Millisecond)
	_, priv, _ := ed25519.GenerateKey(nil)
	srv.SetIntentSigner(priv)

	if _, err := srv.PublishIntents(ctx, corev1.IntentVerb_INTENT_VERB_ELEVATE_SCRUTINY,
		[]string{"sub_b"}, "risk rising", time.Hour); err != nil {
		t.Fatalf("elevate-scrutiny should publish without an approval: %v", err)
	}
}

// TestUnsignedIntentIsNeverPublished / TestBlastRadiusCeiling: the two refusals that bound damage.
func TestUnsignedIntentIsNeverPublished(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	if _, err := srv.PublishIntents(context.Background(), corev1.IntentVerb_INTENT_VERB_ELEVATE_SCRUTINY,
		[]string{"sub_c"}, "", time.Hour); !errors.Is(err, controlplane.ErrIntentUnsigned) {
		t.Fatalf("err = %v, want ErrIntentUnsigned — an unsigned containment signal is a forgery target", err)
	}
}

func TestBlastRadiusCeilingRefusesBeforePublishing(t *testing.T) {
	srv := controlplane.New(requireDB(t))
	_, priv, _ := ed25519.GenerateKey(nil)
	srv.SetIntentSigner(priv)
	srv.SetIntentBlastRadius(3)

	subjects := []string{"a", "b", "c", "d"}
	published, err := srv.PublishIntents(context.Background(), corev1.IntentVerb_INTENT_VERB_ELEVATE_SCRUTINY,
		subjects, "", time.Hour)
	if !errors.Is(err, controlplane.ErrBlastRadius) {
		t.Fatalf("err = %v, want ErrBlastRadius", err)
	}
	if len(published) != 0 {
		t.Errorf("%d intents were published before the ceiling refused — an over-broad request must be "+
			"refused as a WHOLE, not partially enacted across the first N subjects", len(published))
	}
}

// TestForgedIntentIsRejectedAndCounted: the consumer half. A signature proves ORIGIN — an intent that does
// not verify is not from the control plane.
//
// Mutation: skip verification → the forged intent becomes policy context → this FAILS.
func TestForgedIntentIsRejectedAndCounted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	store := intent.NewStore()
	sub := intent.NewSubscriber(pub, store)

	valid := signedIntent(t, priv, corev1.IntentVerb_INTENT_VERB_CONTAIN, "sub_x", 1, time.Now().Add(time.Hour))
	if err := sub.Apply(valid); err != nil {
		t.Fatalf("a valid intent was rejected: %v", err)
	}
	if store.Get("sub_x") != corev1.IntentVerb_INTENT_VERB_CONTAIN {
		t.Fatal("a valid intent did not become policy context")
	}

	// A DIFFERENT key signs: a forgery.
	_, forgerKey, _ := ed25519.GenerateKey(nil)
	forged := signedIntent(t, forgerKey, corev1.IntentVerb_INTENT_VERB_CONTAIN, "sub_y", 1, time.Now().Add(time.Hour))
	if err := sub.Apply(forged); err == nil {
		t.Fatal("a forged intent was accepted")
	}
	if store.Get("sub_y") != corev1.IntentVerb_INTENT_VERB_UNSPECIFIED {
		t.Fatal("a forged intent became policy context — anyone on the bus could contain a host")
	}
	if sub.Rejected.Load() == 0 {
		t.Error("the forgery was not counted; a forged-intent flood must be observable")
	}

	// An unknown version is rejected rather than partially applied.
	future := signedIntent(t, priv, corev1.IntentVerb_INTENT_VERB_CONTAIN, "sub_z", 99, time.Now().Add(time.Hour))
	if err := sub.Apply(future); !errors.Is(err, intent.ErrIntentVersion) {
		t.Errorf("unknown version err = %v, want ErrIntentVersion", err)
	}
}

// TestExpiredIntentIsNotInEffect: a stale containment must not outlive the control plane that issued it.
//
// Mutation: ignore expires_at on read → the expired intent still contains → this FAILS.
func TestExpiredIntentIsNotInEffect(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	store := intent.NewStore()
	sub := intent.NewSubscriber(pub, store)

	expired := signedIntent(t, priv, corev1.IntentVerb_INTENT_VERB_CONTAIN, "sub_old", 1, time.Now().Add(-time.Minute))
	if err := sub.Apply(expired); err != nil {
		t.Fatalf("an expired intent should still be stored (and read as absent): %v", err)
	}
	if got := store.Get("sub_old"); got != corev1.IntentVerb_INTENT_VERB_UNSPECIFIED {
		t.Fatalf("an EXPIRED intent reads as %v — a stale containment must not outlive its TTL", got)
	}
}

// signedIntent builds a control-plane-signed intent for the consumer tests.
func signedIntent(t *testing.T, priv ed25519.PrivateKey, verb corev1.IntentVerb, subject string,
	version uint32, expires time.Time) []byte {
	t.Helper()
	payload, err := proto.Marshal(&corev1.ResponseIntent{
		IntentId: "i-" + subject, Verb: verb, Subject: subject, Version: version,
		IssuedAt: timestamppb.New(time.Now()), ExpiresAt: timestamppb.New(expires),
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
