package postgres

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Ledger is the PostgreSQL audit ledger.
type Ledger struct {
	pool *pgxpool.Pool

	mu     sync.Mutex // appends are serialised: the chain has one tail
	signer *core.Signer
	seq    uint64
	prev   []byte

	// EpochEntries is how many entries share a signing key before it evolves.
	//
	// THIS IS A SECURITY PARAMETER, not a tuning knob. It is the compromise
	// window: an attacker who takes the host can forge any entry written in the
	// CURRENT epoch, because that epoch's private key is still in memory. Every
	// earlier epoch's key has been destroyed and is unforgeable.
	//
	// Smaller means a narrower window and a longer public-key chain to verify;
	// the chain costs one signature verification per epoch, which is cheap
	// enough that the default errs small.
	//
	// A Signer that never evolves has NO forward integrity in practice — the
	// key that signed entry 0 is still resident at entry 10,000. That is why
	// this defaults to a finite value rather than to "never".
	EpochEntries uint64
	sinceEpoch   uint64
}

// DefaultEpochEntries bounds how much recent history a host compromise can
// rewrite. Chosen small enough that the exposed window is a short burst of
// activity rather than a session's worth.
const DefaultEpochEntries = 1000

// Open connects, migrates, and resumes the chain from whatever is already
// stored — so a restart continues the chain rather than starting a second one.
// Open connects and migrates. The Signer holds only the current private key —
// no master secret is retained, which is the property the earlier symmetric
// implementation failed to provide.
func Open(ctx context.Context, dsn string, signer *core.Signer) (*Ledger, error) {
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

	l := &Ledger{pool: pool, signer: signer, EpochEntries: DefaultEpochEntries}
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

	// Seal over the timestamp that will actually be STORED, not the one handed
	// in. PostgreSQL TIMESTAMPTZ has microsecond resolution; the canonical
	// encoding commits to nanoseconds. Hashing the nanosecond value would make
	// every entry written with a real time.Now() verify as tampered the moment
	// it was read back — the chain would be broken by its own storage layer.
	//
	// Truncating here rather than in core is deliberate: the precision limit
	// belongs to this store, and core must not be shaped by a database it is
	// forbidden to import.
	e.AppendedAt = e.AppendedAt.UTC().Truncate(time.Microsecond)

	l.signer.Seal(e, l.prev)

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
			sequence, appended_at, prev_hash, hash, sig, key_epoch,
			decision_id, event_id, action, confidence, reason, policy_id, policy_version,
			outcome_kind, outcome_stage,
			subject_id, purpose, retention_class, context_version
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		int64(e.Sequence), e.AppendedAt, e.PrevHash, e.Hash, e.Sig, int64(e.KeyEpoch),
		decisionID, eventID, action, confidence, reason, policyID, policyVersion,
		e.OutcomeKind, e.OutcomeStage,
		e.SubjectID, int32(e.Purpose), int32(e.Retention), e.ContextVersion)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrAppendFailed, err)
	}

	l.seq++
	l.prev = e.Hash

	// Evolve AFTER the entry is durably stored, never before. Evolving first
	// would destroy the key that signed the entry we are about to fail to
	// write, leaving a retry unable to reproduce it.
	l.sinceEpoch++
	if l.EpochEntries > 0 && l.sinceEpoch >= l.EpochEntries {
		if err := l.signer.Evolve(); err != nil {
			// The entry IS recorded; only the key rotation failed. Returning an
			// error here would tell the caller the append failed, which is
			// false — but staying silent would let the compromise window grow
			// without bound. So: report it, and let the caller see a widened
			// window rather than a phantom lost entry.
			return fmt.Errorf("entry %d recorded, but key evolution failed — the "+
				"compromise window is no longer bounded by EpochEntries: %w", e.Sequence, err)
		}
		l.sinceEpoch = 0
	}
	return nil
}

// Verify walks the whole chain.
func (l *Ledger) Verify(ctx context.Context) (core.VerifyResult, error) {
	rows, err := l.pool.Query(ctx, `
		SELECT sequence, appended_at, prev_hash, hash, sig, key_epoch,
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
			seq, keyEpoch                                        int64
			e                                                    core.Entry
			decisionID, eventID, reason, policyID, policyVersion *string
			action                                               *int32
			confidence                                           *float64
			purpose, retention                                   int32
		)
		if err := rows.Scan(&seq, &e.AppendedAt, &e.PrevHash, &e.Hash, &e.Sig, &keyEpoch,
			&decisionID, &eventID, &action, &confidence, &reason, &policyID, &policyVersion,
			&e.OutcomeKind, &e.OutcomeStage,
			&e.SubjectID, &purpose, &retention, &e.ContextVersion); err != nil {
			return core.VerifyResult{}, err
		}
		e.Sequence = uint64(seq)
		e.KeyEpoch = uint64(keyEpoch)
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
	//
	// Note the verification path takes only PUBLIC material — the key chain and
	// the anchor. No secret is required, so an auditor or the endpoint itself
	// can run exactly this check.
	return core.VerifyChain(entries, l.signer.Chain(), l.signer.AnchorKey(), false), nil
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
