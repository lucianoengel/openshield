// Package xdr holds the cross-domain (XDR) entity model: a durable device ⋈ user
// graph keyed by the ONE canonical pseudonym derivation (IDENT-1), so every
// domain's detections resolve to the same entity — the foundation the XDR
// correlation lane sits on.
package xdr

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Alias kinds.
const (
	// KindDevice names an entity by a device's canonical pseudonym (pseudonym.Of).
	KindDevice = "device"
	// KindUser names an entity by a user identity.
	KindUser = "user"
)

// Store is the entity graph over a Postgres pool.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore wraps a pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Resolve returns the entity id for an alias, creating the entity on first sight.
// It is atomic under concurrency: a per-alias advisory lock serializes the
// select-or-insert, so two simultaneous first-sight resolutions of the same alias
// yield exactly ONE entity (D2). The same alias always resolves to the same id,
// which is why the canonical pseudonym coalesces a device across domains.
func (s *Store) Resolve(ctx context.Context, kind, value string) (int64, error) {
	if kind == "" || value == "" {
		return 0, errors.New("xdr: resolve needs a non-empty kind and value")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	id, err := resolveTx(ctx, tx, kind, value)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return id, nil
}

// resolveTx resolves-or-creates within an existing transaction, taking the
// per-alias advisory lock first so the select-or-insert is atomic.
func resolveTx(ctx context.Context, tx pgx.Tx, kind, value string) (int64, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, aliasKey(kind, value)); err != nil {
		return 0, fmt.Errorf("xdr: lock alias: %w", err)
	}
	var id int64
	err := tx.QueryRow(ctx, `SELECT entity_id FROM entity_aliases WHERE kind=$1 AND value=$2`, kind, value).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("xdr: select alias: %w", err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO entities DEFAULT VALUES RETURNING id`).Scan(&id); err != nil {
		return 0, fmt.Errorf("xdr: insert entity: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO entity_aliases (entity_id, kind, value) VALUES ($1, $2, $3)`, id, kind, value); err != nil {
		return 0, fmt.Errorf("xdr: insert alias: %w", err)
	}
	return id, nil
}

// Link ties two aliases to the same entity (device ⋈ user), merging their entities
// if separate. It returns the surviving entity id. Both aliases are locked in a
// fixed sorted order so concurrent links of the same pair cannot deadlock (D3); the
// merge repoints the loser's aliases to the older (winner) entity, keeping the
// surviving id stable. Idempotent when already linked.
func (s *Store) Link(ctx context.Context, kindA, valA, kindB, valB string) (int64, error) {
	if kindA == "" || valA == "" || kindB == "" || valB == "" {
		return 0, errors.New("xdr: link needs two non-empty aliases")
	}
	// Lock the two aliases in a deterministic order to avoid deadlock.
	first, second := orderKeys(aliasKey(kindA, valA), aliasKey(kindB, valB))

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)), pg_advisory_xact_lock(hashtext($2))`, first, second); err != nil {
		return 0, fmt.Errorf("xdr: lock aliases: %w", err)
	}
	idA, err := resolveTxNoLock(ctx, tx, kindA, valA)
	if err != nil {
		return 0, err
	}
	idB, err := resolveTxNoLock(ctx, tx, kindB, valB)
	if err != nil {
		return 0, err
	}
	if idA == idB {
		if err := tx.Commit(ctx); err != nil {
			return 0, err
		}
		return idA, nil
	}
	// Merge toward the older (smaller id) entity; repoint the loser's aliases.
	winner, loser := idA, idB
	if loser < winner {
		winner, loser = loser, winner
	}
	if _, err := tx.Exec(ctx, `UPDATE entity_aliases SET entity_id=$1 WHERE entity_id=$2`, winner, loser); err != nil {
		return 0, fmt.Errorf("xdr: merge aliases: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM entities WHERE id=$1`, loser); err != nil {
		return 0, fmt.Errorf("xdr: delete merged entity: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return winner, nil
}

// resolveTxNoLock resolves-or-creates without taking the per-alias lock — the
// caller (Link) already holds both alias locks.
func resolveTxNoLock(ctx context.Context, tx pgx.Tx, kind, value string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `SELECT entity_id FROM entity_aliases WHERE kind=$1 AND value=$2`, kind, value).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("xdr: select alias: %w", err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO entities DEFAULT VALUES RETURNING id`).Scan(&id); err != nil {
		return 0, fmt.Errorf("xdr: insert entity: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO entity_aliases (entity_id, kind, value) VALUES ($1, $2, $3)`, id, kind, value); err != nil {
		return 0, fmt.Errorf("xdr: insert alias: %w", err)
	}
	return id, nil
}

// aliasKey is the advisory-lock key for an alias. The separator only needs to
// disambiguate kind from value for the lock; a rare collision would merely
// over-serialize two unrelated aliases (harmless — advisory locks are never a
// correctness gate here). It avoids NUL, which Postgres rejects in text.
func aliasKey(kind, value string) string { return kind + "\x1f" + value }

func orderKeys(a, b string) (string, string) {
	if a <= b {
		return a, b
	}
	return b, a
}
