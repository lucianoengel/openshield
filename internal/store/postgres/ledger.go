package postgres

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Ledger is the PostgreSQL audit ledger.
type Ledger struct {
	pool *pgxpool.Pool

	mu sync.Mutex // appends are serialised: the chain has one tail

	// signer holds the current private key. It is nil for a verify-only ledger:
	// verification reads the persisted PUBLIC chain and needs no secret, which
	// is the whole point of the asymmetric design (D30). A nil-signer ledger
	// refuses to Append.
	signer *core.Signer
	seq    uint64
	prev   []byte

	// persistedEpoch is the highest epoch index written to key_epochs. The
	// signer's in-memory epoch may be one ahead of it — the key evolves after an
	// entry is durably stored, and the new epoch's public row is written lazily
	// in the transaction of the first entry that uses it, never before.
	persistedEpoch int64

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

	// WitnessPub verifies external anchors (T-019). Empty until a witness is
	// configured — with no witness, anchors cannot be validated and completeness
	// stays UNVERIFIED, which is the honest default.
	WitnessPub ed25519.PublicKey
}

// DefaultEpochEntries bounds how much recent history a host compromise can
// rewrite. Chosen small enough that the exposed window is a short burst of
// activity rather than a session's worth.
const DefaultEpochEntries = 1000

// ErrCannotResumeWriting is returned when Open is given a signer that does not
// hold the stored chain's keys. Continuing to write would start a second chain
// under a new anchor while reusing sequence numbers — silent corruption.
// Surviving key material across a restart is T-017; until then, writing resumes
// only in-process, with the same signer that wrote the earlier entries.
var ErrCannotResumeWriting = errors.New("postgres: signer does not hold the stored chain's keys (T-017)")

// Open connects, migrates, and prepares the ledger for WRITING.
//
// The signer holds only the current private key — no master secret is retained,
// which is the property the earlier symmetric implementation failed to provide.
// On an empty database the signer's anchor epoch is persisted. On a non-empty
// database the signer must already hold that chain (same-process resume); a
// signer whose anchor differs is refused rather than allowed to fork the chain.
func Open(ctx context.Context, dsn string, signer *core.Signer) (*Ledger, error) {
	if signer == nil {
		return nil, errors.New("postgres: Open requires a signer; use OpenForVerify for read-only verification")
	}
	l, err := openPool(ctx, dsn, signer)
	if err != nil {
		return nil, err
	}
	if err := l.prepareForWriting(ctx); err != nil {
		l.pool.Close()
		return nil, err
	}
	return l, nil
}

// OpenForVerify connects and migrates for READ-ONLY verification, holding no
// signer and therefore no secret. This is how the CLI and any independent
// auditor verify: the public-key chain is loaded from the database, and nothing
// in this path can produce a valid entry.
func OpenForVerify(ctx context.Context, dsn string) (*Ledger, error) {
	return openPool(ctx, dsn, nil)
}

func openPool(ctx context.Context, dsn string, signer *core.Signer) (*Ledger, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	// SEC-6: migrations are an OWNER operation (they CREATE TABLE / triggers / roles). The
	// APP should run under a NON-OWNER login role (a member of openshield_writer) that can
	// INSERT and tombstone but cannot ALTER the table or disable the append-only trigger —
	// closing 010's owner-bypass residual. A non-owner cannot run Migrate (its CREATE
	// statements are denied), so Open MIGRATES ONLY WHEN NEEDED: a read-only check skips it on
	// an already-migrated database, letting a writer-role app Open without owner rights. The
	// deploy runs migrations once with the owner DSN, then points the app at the writer DSN.
	if done, err := fullyMigrated(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	} else if !done {
		if err := Migrate(ctx, pool); err != nil {
			pool.Close()
			return nil, err
		}
	}
	return &Ledger{pool: pool, signer: signer, EpochEntries: DefaultEpochEntries}, nil
}

// prepareForWriting persists the anchor on an empty database, or confirms the
// provided signer holds the stored chain before allowing appends to continue it.
func (l *Ledger) prepareForWriting(ctx context.Context) error {
	var entryCount, epochCount int64
	if err := l.pool.QueryRow(ctx, `SELECT count(*) FROM audit_entries`).Scan(&entryCount); err != nil {
		return fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	if err := l.pool.QueryRow(ctx, `SELECT count(*) FROM key_epochs`).Scan(&epochCount); err != nil {
		return fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}

	if epochCount == 0 {
		// Fresh database: persist the anchor epoch so the very first entry has a
		// stored epoch to reference.
		anchor := l.signer.Chain()[0]
		if _, err := l.pool.Exec(ctx,
			`INSERT INTO key_epochs (idx, public_key, sig_by_prev) VALUES ($1,$2,$3)`,
			int64(anchor.Index), []byte(anchor.PublicKey), anchor.SigByPrev); err != nil {
			return fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
		}
		l.seq = 0
		l.prev = core.GenesisHash[:]
		l.persistedEpoch = 0
		return nil
	}

	// Existing chain: the signer must be the one that owns it, or writing would
	// fork it. Compare the stored anchor to the signer's.
	storedAnchor, err := l.storedAnchor(ctx)
	if err != nil {
		return err
	}
	if !l.signer.AnchorKey().Equal(storedAnchor) {
		return ErrCannotResumeWriting
	}
	if err := l.resumeTail(ctx); err != nil {
		return err
	}
	return l.pool.QueryRow(ctx, `SELECT max(idx) FROM key_epochs`).Scan(&l.persistedEpoch)
}

// StoredAnchor returns the persisted anchor (epoch 0) public key, for an
// operator capturing it out-of-band. It is public material; exporting it
// reveals no secret.
func (l *Ledger) StoredAnchor(ctx context.Context) (ed25519.PublicKey, error) {
	return l.storedAnchor(ctx)
}

func (l *Ledger) storedAnchor(ctx context.Context) (ed25519.PublicKey, error) {
	var pk []byte
	if err := l.pool.QueryRow(ctx,
		`SELECT public_key FROM key_epochs WHERE idx = 0`).Scan(&pk); err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	return ed25519.PublicKey(pk), nil
}

func (l *Ledger) resumeTail(ctx context.Context) error {
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
//
// The whole operation is one transaction: any epoch public key this entry's
// epoch needs is persisted alongside the entry, so an entry can never be
// committed referencing an epoch the database lacks. The signing key evolves
// only AFTER the transaction commits — evolving first would destroy the key
// that signed an entry we might yet fail to store.
func (l *Ledger) Append(ctx context.Context, e *core.Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.signer == nil {
		return fmt.Errorf("%w: ledger opened for verification only", core.ErrAppendFailed)
	}

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

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrAppendFailed, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful Commit

	// Persist any epoch rows this entry's epoch depends on but the database does
	// not yet have. In practice this is the newly evolved epoch from the
	// previous append; persisting it here, in the transaction of the first entry
	// that uses it, is what keeps the foreign key satisfiable without ever
	// destroying a still-needed private key.
	if err := l.persistEpochsThrough(ctx, tx, int64(e.KeyEpoch)); err != nil {
		return fmt.Errorf("%w: %v", core.ErrAppendFailed, err)
	}

	if err := insertEntry(ctx, tx, e); err != nil {
		return fmt.Errorf("%w: %v", core.ErrAppendFailed, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: %v", core.ErrAppendFailed, err)
	}
	if int64(e.KeyEpoch) > l.persistedEpoch {
		l.persistedEpoch = int64(e.KeyEpoch)
	}

	l.seq++
	l.prev = e.Hash

	// Evolve AFTER the entry is durably committed. Its public row will be
	// written in the next append's transaction, before any entry references it.
	l.sinceEpoch++
	if l.EpochEntries > 0 && l.sinceEpoch >= l.EpochEntries {
		if err := l.signer.Evolve(); err != nil {
			return fmt.Errorf("entry %d recorded, but key evolution failed — the "+
				"compromise window is no longer bounded by EpochEntries: %w", e.Sequence, err)
		}
		l.sinceEpoch = 0
	}
	return nil
}

// persistEpochsThrough writes any key_epochs rows in (persistedEpoch, want]
// using the signer's in-memory chain, within the given transaction.
func (l *Ledger) persistEpochsThrough(ctx context.Context, tx pgx.Tx, want int64) error {
	if want <= l.persistedEpoch {
		return nil
	}
	chain := l.signer.Chain()
	for idx := l.persistedEpoch + 1; idx <= want; idx++ {
		if idx >= int64(len(chain)) {
			return fmt.Errorf("epoch %d needed but not in the signer's chain", idx)
		}
		ep := chain[idx]
		if _, err := tx.Exec(ctx,
			`INSERT INTO key_epochs (idx, public_key, sig_by_prev) VALUES ($1,$2,$3)`,
			int64(ep.Index), []byte(ep.PublicKey), ep.SigByPrev); err != nil {
			return err
		}
	}
	return nil
}

func insertEntry(ctx context.Context, tx pgx.Tx, e *core.Entry) error {
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
	_, err := tx.Exec(ctx, `
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
	return err
}

// loadChain reads the persisted public-key chain. No secret is involved, which
// is exactly why a separate process can verify.
func (l *Ledger) loadChain(ctx context.Context) ([]core.KeyEpoch, error) {
	rows, err := l.pool.Query(ctx,
		`SELECT idx, public_key, sig_by_prev FROM key_epochs ORDER BY idx ASC`)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	defer rows.Close()

	var chain []core.KeyEpoch
	for rows.Next() {
		var idx int64
		var pk, sig []byte
		if err := rows.Scan(&idx, &pk, &sig); err != nil {
			return nil, err
		}
		chain = append(chain, core.KeyEpoch{
			Index: uint64(idx), PublicKey: ed25519.PublicKey(pk), SigByPrev: sig,
		})
	}
	return chain, rows.Err()
}

// Verify walks the whole chain, pinned to expectedAnchor when one is supplied.
//
// The chain and the anchor both come from the PERSISTED public material, not
// from any in-memory signer, so this succeeds even on a ledger opened for
// verification only. Completeness stays UNVERIFIED regardless of the anchor:
// pinning the genesis key proves where the chain starts, not that nothing was
// removed between here and an external witness (T-019).
func (l *Ledger) Verify(ctx context.Context, expectedAnchor ed25519.PublicKey) (core.VerifyResult, error) {
	chain, err := l.loadChain(ctx)
	if err != nil {
		return core.VerifyResult{}, err
	}

	entries, err := l.loadEntries(ctx)
	if err != nil {
		return core.VerifyResult{}, err
	}

	// A nil expectedAnchor means the caller did not bring an out-of-band anchor,
	// so we can only check internal consistency against the chain's own declared
	// start. Say so in the result: this is the honest degraded mode, and a
	// caller must not read it as "the chain starts where it should".
	anchor := expectedAnchor
	selfAnchored := false
	if anchor == nil {
		if len(chain) > 0 {
			anchor = chain[0].PublicKey
		}
		selfAnchored = true
	}

	anchors, err := l.loadAnchors(ctx)
	if err != nil {
		return core.VerifyResult{}, err
	}

	res := core.VerifyChain(entries, chain, anchor, anchors, l.WitnessPub)
	// The self-anchored (key-anchor) note applies only while completeness is not
	// externally attested; an anchored chain has a stronger story to tell.
	if selfAnchored && res.Consistent && res.Completeness != core.CompletenessAnchored {
		res.Reason = "no external anchor supplied: internal consistency only, completeness and origin unverified"
	}
	return res, nil
}

func (l *Ledger) loadEntries(ctx context.Context) ([]*core.Entry, error) {
	rows, err := l.pool.Query(ctx, `
		SELECT sequence, appended_at, prev_hash, hash, sig, key_epoch,
		       decision_id, event_id, action, confidence, reason, policy_id, policy_version,
		       outcome_kind, outcome_stage,
		       subject_id, purpose, retention_class, context_version,
		       tombstoned_at
		FROM audit_entries ORDER BY sequence ASC`)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
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
			tombstonedAt                                         *time.Time
		)
		if err := rows.Scan(&seq, &e.AppendedAt, &e.PrevHash, &e.Hash, &e.Sig, &keyEpoch,
			&decisionID, &eventID, &action, &confidence, &reason, &policyID, &policyVersion,
			&e.OutcomeKind, &e.OutcomeStage,
			&e.SubjectID, &purpose, &retention, &e.ContextVersion,
			&tombstonedAt); err != nil {
			return nil, err
		}
		e.Sequence = uint64(seq)
		e.Tombstoned = tombstonedAt != nil
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
	return entries, rows.Err()
}

// loadAnchors reads the persisted external anchors (T-019). Public material —
// no secret is involved, so a verifier holding no key can still use them.
func (l *Ledger) loadAnchors(ctx context.Context) ([]core.Anchor, error) {
	rows, err := l.pool.Query(ctx, `SELECT sequence, hash, witness_sig FROM anchors ORDER BY sequence ASC`)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrLedgerUnavailable, err)
	}
	defer rows.Close()
	var out []core.Anchor
	for rows.Next() {
		var seq int64
		var hash, sig []byte
		if err := rows.Scan(&seq, &hash, &sig); err != nil {
			return nil, err
		}
		out = append(out, core.Anchor{Sequence: uint64(seq), Hash: hash, WitnessSig: sig})
	}
	return out, rows.Err()
}

// AnchorHead witnesses the current ledger head and stores the anchor. The
// witness MUST be provisioned in a trust domain the deployer does not control;
// an anchor witnessed by a key the deployer holds attests to nothing (T-019).
//
// The undetectable-loss window is the interval between AnchorHead calls:
// everything appended since the last anchor can still be truncated without
// detection. Callers choosing that interval are choosing that window.
func (l *Ledger) AnchorHead(ctx context.Context, w *core.Witness) (core.Anchor, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var seq int64
	var hash []byte
	if err := l.pool.QueryRow(ctx,
		`SELECT sequence, hash FROM audit_entries ORDER BY sequence DESC LIMIT 1`).Scan(&seq, &hash); err != nil {
		return core.Anchor{}, fmt.Errorf("%w: reading head to anchor: %v", core.ErrLedgerUnavailable, err)
	}
	a := w.Anchor(uint64(seq), hash)
	if _, err := l.pool.Exec(ctx,
		`INSERT INTO anchors (sequence, hash, witness_sig) VALUES ($1,$2,$3)`,
		int64(a.Sequence), a.Hash, a.WitnessSig); err != nil {
		return core.Anchor{}, fmt.Errorf("%w: storing anchor: %v", core.ErrLedgerUnavailable, err)
	}
	return a, nil
}

// Purge tombstones every live entry past its retention age (T-013), erasing the
// personal-data columns while keeping the chain skeleton (sequence, prev_hash,
// hash, sig, key_epoch) so verification stays intact across the erasure.
// Investigation-class entries are HELD — never purged by routine retention.
//
// It returns the number of entries tombstoned and is idempotent: an
// already-tombstoned entry is not selected again (the WHERE clause requires a
// live row past its age).
//
// Deleting rather than tombstoning would break the chain irreparably — later
// entries link to hashes this row carries. That tension between GDPR erasure and
// a hash chain is the whole reason this is a tombstone and not a DELETE (D36).
func (l *Ledger) Purge(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	// Each bounded class is purged with its own age cutoff. Investigation is
	// absent from this loop by construction — a held class has no cutoff.
	for _, class := range []core.RetentionClass{
		core.RetentionUnspecified, core.RetentionShort, core.RetentionStandard,
	} {
		maxAge, bounded := class.MaxAge()
		if !bounded {
			continue
		}
		cutoff := now.Add(-maxAge)
		// SEC-5: never tombstone an entry whose subject is under an ACTIVE legal hold
		// (HON-2's registry), even if its class is routine and its age is past. An entry's
		// retention_class is immutable (migration 010), so a hold placed AFTER the entry was
		// written cannot change its class — the registry is the only way to protect it. Age
		// enforcement stays here; the hold is an override.
		tag, err := l.pool.Exec(ctx, `
			UPDATE audit_entries
			SET tombstoned_at = $1,
			    subject_id = '', decision_id = NULL, event_id = NULL,
			    reason = NULL, policy_id = NULL, policy_version = NULL,
			    action = NULL, confidence = NULL, purpose = 0,
			    outcome_kind = '', outcome_stage = ''
			WHERE tombstoned_at IS NULL
			  AND retention_class = $2
			  AND appended_at < $3
			  AND subject_id NOT IN (SELECT subject_id FROM legal_holds WHERE released_at IS NULL)`,
			now.UTC(), int32(class), cutoff.UTC())
		if err != nil {
			return total, fmt.Errorf("%w: purge class %d: %v", core.ErrLedgerUnavailable, class, err)
		}
		total += tag.RowsAffected()
	}
	return total, nil
}

// RecordView appends an entry recording that an investigation was viewed (D20).
// The view itself is a chained, tamper-evident entry. `viewer` should carry the
// OS user labelled unauthenticated until real identity exists (T-017) — an
// unlabelled identity here would misrepresent accountability the system does not
// yet have.
func (l *Ledger) RecordView(ctx context.Context, viewer string) error {
	return l.Append(ctx, &core.Entry{
		AppendedAt:   time.Now().UTC(),
		OutcomeKind:  "investigation-viewed",
		OutcomeStage: viewer,
		Retention:    core.RetentionStandard,
	})
}

// Entries returns the ledger entries in sequence order, for a read surface such
// as the timeline CLI. Verification is a separate call — a reader must decide
// what to render, but only after Verify has told it what is trustworthy.
func (l *Ledger) Entries(ctx context.Context) ([]*core.Entry, error) {
	return l.loadEntries(ctx)
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
