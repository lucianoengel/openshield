package controlplane_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/controlplane"
)

func enrolledAgent(t *testing.T, srv *controlplane.Server, agentID string) *identity.Identity {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	tok, err := srv.IssueToken(ctx, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate(agentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Enroll(ctx, tok, agentID, id.PublicKey(), now); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return id
}

// A token enrolls once, then is spent; an expired token fails; the store holds a
// hash, not the token.
func TestEnrollmentSingleUse(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now()

	tok, err := srv.IssueToken(ctx, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.Generate("agent-1")
	if err := srv.Enroll(ctx, tok, "agent-1", id.PublicKey(), now); err != nil {
		t.Fatalf("first enroll should succeed: %v", err)
	}
	// Second use of the same token must fail.
	id2, _ := identity.Generate("agent-2")
	if err := srv.Enroll(ctx, tok, "agent-2", id2.PublicKey(), now); !errors.Is(err, controlplane.ErrEnrollment) {
		t.Errorf("second enroll err = %v, want ErrEnrollment — a token must be single-use", err)
	}

	// An expired token fails.
	expTok, _ := srv.IssueToken(ctx, time.Millisecond, now.Add(-time.Hour))
	id3, _ := identity.Generate("agent-3")
	if err := srv.Enroll(ctx, expTok, "agent-3", id3.PublicKey(), now); !errors.Is(err, controlplane.ErrEnrollment) {
		t.Errorf("expired token enroll err = %v, want ErrEnrollment", err)
	}

	// The store holds a hash, not the raw token.
	hash := sha256.Sum256([]byte(tok))
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT token_hash FROM enrollment_tokens WHERE token_hash = $1`, hash[:]).Scan(&raw); err != nil {
		t.Fatalf("token hash not found: %v", err)
	}
	var anyPlain int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM enrollment_tokens WHERE token_hash = $1`, []byte(tok)).Scan(&anyPlain)
	if anyPlain != 0 {
		t.Error("the raw token appears in the store — only a hash may be stored")
	}
}

// In-order signed telemetry is accepted and advances; a wrong signature is
// rejected; a gap is accepted-and-recorded; a replay is rejected.
func TestVerifySignedAndGaps(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now()
	id := enrolledAgent(t, srv, "agent-sig")

	payload := []byte("telemetry-1")
	// seq 1 in order.
	if _, err := srv.VerifySigned(ctx, "agent-sig", 1, payload, id.Sign(1, payload), now); err != nil {
		t.Fatalf("in-order seq 1: %v", err)
	}
	// A wrong signature is rejected (sign a different payload).
	if _, err := srv.VerifySigned(ctx, "agent-sig", 2, payload, id.Sign(2, []byte("other")), now); !errors.Is(err, controlplane.ErrBadSignature) {
		t.Errorf("wrong-sig err = %v, want ErrBadSignature", err)
	}
	// A GAP: jump to seq 5 (expected 2) — accepted, gap recorded.
	res, err := srv.VerifySigned(ctx, "agent-sig", 5, payload, id.Sign(5, payload), now)
	if err != nil {
		t.Fatalf("gap seq 5: %v", err)
	}
	if !res.Gap || res.GapSize != 3 {
		t.Errorf("gap = %+v, want Gap=true GapSize=3 (2,3,4 suppressed)", res)
	}
	// A REPLAY: seq 5 again (<= last) — rejected.
	if _, err := srv.VerifySigned(ctx, "agent-sig", 5, payload, id.Sign(5, payload), now); !errors.Is(err, controlplane.ErrReplay) {
		t.Errorf("replay err = %v, want ErrReplay", err)
	}
	// seq 3 (below last=5) — also a replay/reorder, rejected.
	if _, err := srv.VerifySigned(ctx, "agent-sig", 3, payload, id.Sign(3, payload), now); !errors.Is(err, controlplane.ErrReplay) {
		t.Errorf("reorder err = %v, want ErrReplay", err)
	}
}

// A revoked agent is rejected; another agent still verifies.
func TestRevocation(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now()
	a := enrolledAgent(t, srv, "agent-revoke")
	b := enrolledAgent(t, srv, "agent-keep")

	payload := []byte("t")
	if _, err := srv.VerifySigned(ctx, "agent-revoke", 1, payload, a.Sign(1, payload), now); err != nil {
		t.Fatal(err)
	}
	if err := srv.Revoke(ctx, "agent-revoke", now); err != nil {
		t.Fatal(err)
	}
	// Revoked agent's next (validly signed) message is rejected.
	if _, err := srv.VerifySigned(ctx, "agent-revoke", 2, payload, a.Sign(2, payload), now); !errors.Is(err, controlplane.ErrRevoked) {
		t.Errorf("revoked agent err = %v, want ErrRevoked", err)
	}
	// The other agent is unaffected.
	if _, err := srv.VerifySigned(ctx, "agent-keep", 1, payload, b.Sign(1, payload), now); err != nil {
		t.Errorf("revoking one agent broke another: %v", err)
	}
	// An unknown agent is rejected.
	c, _ := identity.Generate("agent-unknown")
	if _, err := srv.VerifySigned(ctx, "agent-unknown", 1, payload, c.Sign(1, payload), now); !errors.Is(err, controlplane.ErrUnknownAgent) {
		t.Errorf("unknown agent err = %v, want ErrUnknownAgent", err)
	}
}
