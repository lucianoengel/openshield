package controlplane_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SEC-2: a fresh enrollment token must NOT be able to overwrite an existing agent's key
// (and thereby sign telemetry as it) or un-revoke a revoked agent. Re-enrollment of an
// existing id is refused with ErrAgentExists; the original key still verifies.
func TestEnrollCannotHijackExistingAgent(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now()

	// Legitimate agent-1 enrolls with its own key.
	tok1, _ := srv.IssueToken(ctx, time.Hour, now)
	victim, _ := identity.Generate("agent-1")
	if err := srv.Enroll(ctx, tok1, "agent-1", victim.PublicKey(), now); err != nil {
		t.Fatal(err)
	}

	// Attacker obtains a DIFFERENT valid token and tries to re-enroll "agent-1" with THEIR
	// key — the hijack. It must be refused.
	tok2, _ := srv.IssueToken(ctx, time.Hour, now)
	attacker, _ := identity.Generate("agent-1")
	if err := srv.Enroll(ctx, tok2, "agent-1", attacker.PublicKey(), now); !errors.Is(err, controlplane.ErrAgentExists) {
		t.Fatalf("hijack enroll err = %v, want ErrAgentExists", err)
	}

	// The victim's key still verifies telemetry; the attacker's does not.
	payload := []byte("evt")
	vSig := victim.Sign(1, payload)
	if _, err := srv.VerifySigned(ctx, "agent-1", 1, payload, vSig, now); err != nil {
		t.Errorf("victim key no longer verifies after the hijack attempt: %v", err)
	}
	aSig := attacker.Sign(2, payload)
	if _, err := srv.VerifySigned(ctx, "agent-1", 2, payload, aSig, now); err == nil {
		t.Error("the attacker's key verifies — the hijack succeeded")
	}
}

// A revoked agent stays revoked: a fresh token cannot un-revoke it by re-enrolling.
func TestEnrollCannotUnrevoke(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now()

	tok, _ := srv.IssueToken(ctx, time.Hour, now)
	id, _ := identity.Generate("agent-x")
	if err := srv.Enroll(ctx, tok, "agent-x", id.PublicKey(), now); err != nil {
		t.Fatal(err)
	}
	if err := srv.Revoke(ctx, "agent-x", now); err != nil {
		t.Fatal(err)
	}

	// A new token trying to re-enroll (and thus un-revoke) agent-x is refused.
	tok2, _ := srv.IssueToken(ctx, time.Hour, now)
	if err := srv.Enroll(ctx, tok2, "agent-x", id.PublicKey(), now); !errors.Is(err, controlplane.ErrAgentExists) {
		t.Fatalf("re-enroll of revoked agent err = %v, want ErrAgentExists", err)
	}
	// It is still revoked.
	sig := id.Sign(5, []byte("p"))
	if _, err := srv.VerifySigned(ctx, "agent-x", 5, []byte("p"), sig, now); !errors.Is(err, controlplane.ErrRevoked) {
		t.Errorf("agent-x telemetry err = %v, want ErrRevoked (un-revoke succeeded)", err)
	}
}
