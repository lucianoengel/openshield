package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/pseudonym"
)

var (
	// ErrEnrollment covers a token that is missing, expired or already used.
	ErrEnrollment = errors.New("controlplane: enrollment token invalid, expired or used")
	// ErrUnknownAgent is returned when verifying telemetry for an agent that was
	// never enrolled.
	ErrUnknownAgent = errors.New("controlplane: unknown agent")
	// ErrRevoked is returned for a revoked agent's telemetry.
	ErrRevoked = errors.New("controlplane: agent identity revoked")
	// ErrAgentExists is returned when enrollment would overwrite an EXISTING agent's
	// identity (SEC-2). Enrollment records a NEW identity; overwriting an existing key or
	// un-revoking a revoked agent must be an explicit, audited operator action, never an
	// implicit upsert — otherwise any fresh token can hijack any agent id.
	ErrAgentExists = errors.New("controlplane: agent id already enrolled (re-enrollment is an operator action)")
	// ErrBadSignature is returned when a telemetry signature does not verify.
	ErrBadSignature = errors.New("controlplane: telemetry signature invalid")
	// ErrReplay is returned for a sequence at or below the last seen — a replay
	// or reorder, which must not be accepted.
	ErrReplay = errors.New("controlplane: telemetry sequence replay/reorder")
)

// IssueToken creates a single-use, short-TTL enrollment token. It returns the
// token to the caller (the admin) and stores ONLY its hash — a leaked database
// does not leak usable tokens.
func (s *Server) IssueToken(ctx context.Context, ttl time.Duration, now time.Time) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO enrollment_tokens (token_hash, expires_at) VALUES ($1,$2)`,
		hash[:], now.Add(ttl).UTC()); err != nil {
		return "", fmt.Errorf("controlplane: storing token: %w", err)
	}
	return token, nil
}

// Enroll binds an agent's public key to its id using a token. The token is
// verified (present, unexpired, unused) and BURNED in the same transaction as
// the identity insert, so a second enroll with the same token finds it used.
func (s *Server) Enroll(ctx context.Context, token, agentID string, pub ed25519.PublicKey, now time.Time) error {
	hash := sha256.Sum256([]byte(token))
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(ctx,
		`SELECT expires_at, used_at FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE`,
		hash[:]).Scan(&expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEnrollment
	}
	if err != nil {
		return err
	}
	if usedAt != nil || now.After(expiresAt) {
		return ErrEnrollment
	}

	// SEC-2: refuse to overwrite an existing agent id. ON CONFLICT DO NOTHING + a zero
	// row count means the id is already enrolled — a fresh token must NOT be able to
	// replace an agent's key or un-revoke a revoked agent (then sign telemetry as it).
	// Re-enrollment is a deliberate operator action (revoke/delete the old identity first).
	ct, err := tx.Exec(ctx,
		`INSERT INTO agent_identities (agent_id, public_key) VALUES ($1,$2)
		 ON CONFLICT (agent_id) DO NOTHING`,
		agentID, []byte(pub))
	if err != nil {
		return fmt.Errorf("controlplane: recording identity: %w", err)
	}
	if ct.RowsAffected() == 0 {
		// The id already exists (or is revoked). Reject WITHOUT consuming the token, so a
		// legitimate holder can still enroll a fresh id — only the hijack is refused.
		return ErrAgentExists
	}
	if _, err := tx.Exec(ctx,
		`UPDATE enrollment_tokens SET used_at = $1 WHERE token_hash = $2`, now.UTC(), hash[:]); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// XDR-1-WIRE: populate the device entity for the newly-enrolled agent, keyed by the ONE canonical
	// pseudonym (IDENT-1) — the same value the engine stamps on events and the gateway derives from the
	// cert CN, so this device coalesces across domains. Best-effort, after commit: a graph write must
	// never fail a real enrollment.
	s.resolveDeviceEntity(ctx, pseudonym.Of(agentID))
	return nil
}

// Revoke marks an agent's identity revoked; its telemetry is thereafter
// rejected. Per-agent, so containing one endpoint does not touch the fleet.
func (s *Server) Revoke(ctx context.Context, agentID string, now time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE agent_identities SET revoked_at = $1 WHERE agent_id = $2`, now.UTC(), agentID)
	return err
}

// SignedResult reports the outcome of verifying a signed telemetry envelope.
type SignedResult struct {
	// Gap is true when the sequence jumped ahead of the next expected one —
	// messages were suppressed between the agent and here. The message is still
	// accepted (it is authentic); the gap is the signal.
	Gap     bool
	GapSize uint64
}

// VerifySigned verifies a signed telemetry envelope: the signature against the
// enrolled (non-revoked) key, and the sequence for gaps and replays.
//
//   - unknown or revoked agent → error
//   - bad signature → error
//   - seq <= last → ErrReplay (a replay/reorder must never be accepted)
//   - seq > last+1 → accepted, Gap reported (suppression detected)
//   - seq == last+1 → accepted, in order
//
// Accepting the message advances last_sequence.
func (s *Server) VerifySigned(ctx context.Context, agentID string, seq uint64, payload, sig []byte, now time.Time) (SignedResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SignedResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	res, err := s.verifySignedTx(ctx, tx, agentID, seq, payload, sig)
	if err != nil {
		return SignedResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SignedResult{}, err
	}
	return res, nil
}

// verifySignedTx is the atomic core of signed-telemetry verification, WITHOUT owning the
// transaction: the advisory lock, identity read, signature/replay check, and monotonic-sequence
// advance all run on the caller's tx. VerifySigned wraps it in a commit-per-call; the durable
// ingest path (R34-4) wraps it in the SAME tx as the telemetry insert, so a transient persist
// failure ROLLS BACK the sequence advance too — otherwise the advance commits, redelivery looks
// like a replay, and the Nak-redelivered message is dropped (the "durable, no loss" claim broken).
func (s *Server) verifySignedTx(ctx context.Context, tx pgx.Tx, agentID string, seq uint64, payload, sig []byte) (SignedResult, error) {
	// Serialize concurrent messages for the SAME agent (the monotonic-sequence check must be
	// atomic) via a per-agent transaction-scoped ADVISORY lock (PLAT-2), instead of a
	// `SELECT … FOR UPDATE` that held the agent_identities ROW lock across the whole transaction
	// (blocking even reads of that identity). hashtext maps the agent id to the lock key; a rare
	// hash collision merely serializes two unrelated agents briefly — never a correctness issue,
	// since the sequence is still checked against the correct row. The lock releases at commit/rollback.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, agentID); err != nil {
		return SignedResult{}, err
	}

	var pub []byte
	var revokedAt *time.Time
	var lastSeq int64
	err := tx.QueryRow(ctx,
		`SELECT public_key, revoked_at, last_sequence FROM agent_identities WHERE agent_id = $1`,
		agentID).Scan(&pub, &revokedAt, &lastSeq)
	if errors.Is(err, pgx.ErrNoRows) {
		return SignedResult{}, ErrUnknownAgent
	}
	if err != nil {
		return SignedResult{}, err
	}
	if revokedAt != nil {
		return SignedResult{}, ErrRevoked
	}

	if !ed25519.Verify(ed25519.PublicKey(pub), identity.CanonicalEnvelope(agentID, seq, payload), sig) {
		return SignedResult{}, ErrBadSignature
	}

	last := uint64(lastSeq)
	if seq <= last {
		return SignedResult{}, ErrReplay
	}
	res := SignedResult{}
	if seq > last+1 {
		res.Gap = true
		res.GapSize = seq - last - 1
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agent_identities SET last_sequence = $1 WHERE agent_id = $2`, int64(seq), agentID); err != nil {
		return SignedResult{}, err
	}
	return res, nil
}
