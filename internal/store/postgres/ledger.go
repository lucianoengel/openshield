package postgres

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Ledger is the PostgreSQL audit ledger.
type Ledger struct {
	pool *pgxpool.Pool
	seed []byte

	mu      sync.Mutex // appends are serialised: the chain has one tail
	ratchet *core.Ratchet
	seq     uint64
	prev    []byte
}

// Open connects, migrates, and resumes the chain from whatever is already
// stored — so a restart continues the chain rather than starting a second one.
func Open(ctx context.Context, dsn string, seed []byte) (*Ledger, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	l := &Ledger{pool: pool, seed: seed}
	if err := l.resume(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return l, nil
}

func (l *Ledger) resume(ctx context.Context) error {
	var count int64
	if err := l.pool.QueryRow(ctx, `SELECT count(*) FROM audit_entries`).Scan(&count); err != nil {
		return fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	if count == 0 {
		l.seq = 0
		l.prev = core.GenesisHash[:]
		l.ratchet = core.NewRatchet(l.seed)
		return nil
	}
	var seq int64
	var hash []byte
	if err := l.pool.QueryRow(ctx,
		`SELECT sequence, hash FROM audit_entries ORDER BY sequence DESC LIMIT 1`).
		Scan(&seq, &hash); err != nil {
		return fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	l.seq = uint64(seq) + 1
	l.prev = hash
	// Fast-forward the ratchet to the position after the last entry. The key
	// for earlier positions is not recoverable from here — that is the point.
	l.ratchet = core.NewRatchet(core.KeyAt(l.seed, l.seq))
	return nil
}

// Append seals and stores an entry.
//
// A failure returns an error and the entry is NOT recorded as if it had
// succeeded: an unrecorded Decision in an observe-only product is
// indistinguishable from an event that never happened.
func (l *Ledger) Append(ctx context.Context, e *core.Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	e.Sequence = l.seq
	key := core.KeyAt(l.seed, l.seq)
	core.Seal(e, l.prev, key)

	d := e.Decision
	var (
		decisionID, eventID, reason, policyID, policyVersion *string
		action                                               *int32
		confidence                                           *float64
	)
	if d != nil {
		s := func(v string) *string { return &v }
		decisionID, eventID = s(d.GetDecisionId()), s(d.GetEventId())
		reason, policyID = s(d.GetReason()), s(d.GetPolicyId())
		policyVersion = s(d.GetPolicyVersion())
		a := int32(d.GetAction())
		c := d.GetConfidence()
		action, confidence = &a, &c
	}

	_, err := l.pool.Exec(ctx, `
		INSERT INTO audit_entries (
			sequence, appended_at, prev_hash, hash, sig,
			decision_id, event_id, action, confidence, reason, policy_id, policy_version,
			outcome_kind, outcome_stage,
			subject_id, purpose, retention_class, context_version
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		int64(e.Sequence), e.AppendedAt, e.PrevHash, e.Hash, e.Sig,
		decisionID, eventID, action, confidence, reason, policyID, policyVersion,
		e.OutcomeKind, e.OutcomeStage,
		e.SubjectID, int32(e.Purpose), int32(e.Retention), e.ContextVersion)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrAppendFailed, err)
	}

	l.seq++
	l.prev = e.Hash
	return nil
}

// Verify walks the whole chain.
func (l *Ledger) Verify(ctx context.Context) (core.VerifyResult, error) {
	rows, err := l.pool.Query(ctx, `
		SELECT sequence, appended_at, prev_hash, hash, sig,
		       decision_id, event_id, action, confidence, reason, policy_id, policy_version,
		       outcome_kind, outcome_stage,
		       subject_id, purpose, retention_class, context_version
		FROM audit_entries ORDER BY sequence ASC`)
	if err != nil {
		return core.VerifyResult{}, fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	defer rows.Close()

	var entries []*core.Entry
	for rows.Next() {
		var (
			seq                                                  int64
			e                                                    core.Entry
			decisionID, eventID, reason, policyID, policyVersion *string
			action                                               *int32
			confidence                                           *float64
			purpose, retention                                   int32
		)
		if err := rows.Scan(&seq, &e.AppendedAt, &e.PrevHash, &e.Hash, &e.Sig,
			&decisionID, &eventID, &action, &confidence, &reason, &policyID, &policyVersion,
			&e.OutcomeKind, &e.OutcomeStage,
			&e.SubjectID, &purpose, &retention, &e.ContextVersion); err != nil {
			return core.VerifyResult{}, err
		}
		e.Sequence = uint64(seq)
		e.Purpose = corev1.Purpose(purpose)
		e.Retention = core.RetentionClass(retention)
		if decisionID != nil {
			e.Decision = &corev1.Decision{
				DecisionId: *decisionID, EventId: deref(eventID),
				Action: corev1.Action(derefI32(action)), Confidence: derefF64(confidence),
				Reason: deref(reason), PolicyId: deref(policyID),
				PolicyVersion: deref(policyVersion), ContextVersion: e.ContextVersion,
			}
		}
		entries = append(entries, &e)
	}
	if err := rows.Err(); err != nil {
		return core.VerifyResult{}, err
	}

	// anchored=false: nothing external attests that entries were not removed
	// wholesale. External anchoring is T-019, and until it exists the honest
	// answer is that completeness is unverified.
	return core.VerifyChain(entries, l.seed, false), nil
}

func (l *Ledger) Close() error {
	l.pool.Close()
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
func derefI32(v *int32) int32 {
	if v == nil {
		return 0
	}
	return *v
}
func derefF64(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

var _ core.Ledger = (*Ledger)(nil)
