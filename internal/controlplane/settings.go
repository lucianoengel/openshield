package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/config"
)

// Database-authoritative dynamic configuration, with revisions (PLAT-5b).
//
// A CHANGE IS A REVISION, NOT A WRITE. Three tables answer three different questions: what is in effect
// (config_settings), who changed it and when (config_revisions), and what it changed FROM (config_changes).
// Rollback restores values as a NEW revision rather than deleting rows — an audit trail you can rewind by
// erasing is not one.

var (
	// ErrNotDynamic means the key is a bootstrap field: it must reach the process before the database
	// does, so it cannot be stored in it.
	ErrNotDynamic = errors.New("controlplane: field is bootstrap-scoped and cannot be stored")
	// ErrSecretNotStorable means the key is a secret. Its value stays in env or a file on the host, so a
	// dump of this database is not a dump of the deployment's credentials.
	ErrSecretNotStorable = errors.New("controlplane: a secret is never stored in the configuration store")
	// ErrUnknownSetting means the key is not declared — storing it would be a value nobody reads.
	ErrUnknownSetting = errors.New("controlplane: not a declared configuration field")
)

// ApplySettings records a configuration change as a revision.
//
// VALIDATED AT SAVE, and REFUSED IN FULL. Every key is checked against the SAME declaration the reader
// uses before anything is written; one bad key refuses the whole change, because partial application
// leaves a deployment in a state no operator chose. Discovering an invalid value at the next restart
// would mean the operator who typed it is not the person who finds out.
func (s *Server) ApplySettings(ctx context.Context, r *config.Resolver, author, note string,
	changes map[string]string) (int64, error) {
	if author == "" {
		return 0, ErrNoViewer
	}
	if len(changes) == 0 {
		return 0, errors.New("controlplane: a configuration change needs at least one key")
	}
	keys := make([]string, 0, len(changes))
	for k := range changes {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic diff order

	// Validate EVERYTHING first. Nothing is written until every key passes.
	for _, k := range keys {
		f, ok := r.Field(k)
		switch {
		case !ok:
			return 0, fmt.Errorf("%w: %q", ErrUnknownSetting, k)
		case f.Secret():
			return 0, fmt.Errorf("%w: %q", ErrSecretNotStorable, k)
		case f.Scope != config.ScopeDynamic:
			return 0, fmt.Errorf("%w: %q", ErrNotDynamic, k)
		}
		if err := f.Check(changes[k]); err != nil {
			return 0, config.Errors{{Key: k, Value: changes[k], Reason: err.Error()}}
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var rev int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO config_revisions (author, note) VALUES ($1,$2) RETURNING id`, author, note).Scan(&rev); err != nil {
		return 0, err
	}
	for _, k := range keys {
		var old string
		// The previous value is captured for the DIFF: "who widened the retention window" needs to say
		// what it was widened FROM.
		_ = tx.QueryRow(ctx, `SELECT value FROM config_settings WHERE key=$1`, k).Scan(&old)
		if _, err := tx.Exec(ctx,
			`INSERT INTO config_changes (revision_id, key, old_value, new_value) VALUES ($1,$2,$3,$4)`,
			rev, k, old, changes[k]); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO config_settings (key, value, revision, updated_at) VALUES ($1,$2,$3, now())
			 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, revision=EXCLUDED.revision,
			     updated_at=now()`, k, changes[k], rev); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return rev, nil
}

// SettingsSnapshot reads the current settings and the revision they are at.
func (s *Server) SettingsSnapshot(ctx context.Context) (*config.Snapshot, error) {
	snap := &config.Snapshot{Values: map[string]string{}}
	rows, err := s.pool.Query(ctx, `SELECT key, value, revision FROM config_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var rev int64
		if err := rows.Scan(&k, &v, &rev); err != nil {
			return nil, err
		}
		snap.Values[k] = v
		if rev > snap.Revision {
			snap.Revision = rev
		}
	}
	return snap, rows.Err()
}

// CurrentRevision is the latest revision id, or 0. The live-apply watcher polls this.
func (s *Server) CurrentRevision(ctx context.Context) (int64, error) {
	var rev int64
	err := s.pool.QueryRow(ctx, `SELECT coalesce(max(id),0) FROM config_revisions`).Scan(&rev)
	return rev, err
}

// ConfigRevision is one recorded change.
type ConfigRevision struct {
	ID      int64          `json:"id"`
	Author  string         `json:"author"`
	Note    string         `json:"note,omitempty"`
	At      time.Time      `json:"at"`
	Changes []ConfigChange `json:"changes"`
}

// ConfigChange is one key's before and after — what makes a revision auditable rather than just dated.
type ConfigChange struct {
	Key string `json:"key"`
	Old string `json:"old_value,omitempty"`
	New string `json:"new_value"`
}

// Revisions returns the change history, newest first.
func (s *Server) Revisions(ctx context.Context, limit int) ([]ConfigRevision, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, author, note, at FROM config_revisions ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	var out []ConfigRevision
	for rows.Next() {
		var r ConfigRevision
		if err := rows.Scan(&r.ID, &r.Author, &r.Note, &r.At); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		crows, err := s.pool.Query(ctx,
			`SELECT key, old_value, new_value FROM config_changes WHERE revision_id=$1 ORDER BY key`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for crows.Next() {
			var c ConfigChange
			if err := crows.Scan(&c.Key, &c.Old, &c.New); err != nil {
				crows.Close()
				return nil, err
			}
			out[i].Changes = append(out[i].Changes, c)
		}
		crows.Close()
	}
	return out, nil
}

// RollbackTo restores the values as they stood AFTER a given revision, recorded as a NEW revision.
//
// History is never deleted. Rolling back by removing revisions would make the audit trail rewritable by
// the same action it is supposed to record.
//
// The honest limit: this restores VALUES, not behaviour. A revision applied while a connector was
// unreachable is not undone by putting the setting back.
func (s *Server) RollbackTo(ctx context.Context, r *config.Resolver, revision int64, author string) (int64, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT ON (key) key, new_value FROM config_changes
		  WHERE revision_id <= $1 ORDER BY key, revision_id DESC`, revision)
	if err != nil {
		return 0, err
	}
	restore := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return 0, err
		}
		restore[k] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(restore) == 0 {
		return 0, fmt.Errorf("controlplane: revision %d has nothing to restore", revision)
	}
	return s.ApplySettings(ctx, r, author, fmt.Sprintf("rollback to revision %d", revision), restore)
}

// LoadSettings loads the current snapshot ONCE, synchronously.
//
// Separate from WatchSettings because a process must read its configuration BEFORE it decides what to
// start. Loading inside the watcher's goroutine leaves the startup path racing the first load: whether
// an operator's saved setting takes effect would then depend on which goroutine won, which is the kind of
// bug that passes every test on an idle machine and misconfigures a busy one.
func (s *Server) LoadSettings(ctx context.Context, db *config.DBSource) {
	rev, err := s.CurrentRevision(ctx)
	if err != nil || rev == db.Revision() {
		return
	}
	snap, err := s.SettingsSnapshot(ctx)
	if err != nil {
		return
	}
	db.Set(snap)
}

// WatchSettings keeps a DBSource current: it polls the revision and swaps an immutable snapshot when it
// changes. THIS IS WHAT MAKES A SAVED SETTING TAKE EFFECT — without it the store is a config file with
// extra steps.
//
// The swap is atomic and the snapshot immutable, so a reader never observes a half-applied revision.
func (s *Server) WatchSettings(ctx context.Context, db *config.DBSource, interval time.Duration) {
	apply := s.LoadSettings
	apply(ctx, db) // load before the first tick, so a restart is current immediately
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			apply(ctx, db)
		}
	}
}

// SchemaSkew is how many migrations the DATABASE has applied that this binary does not embed (PLAT-9).
//
// Non-zero means a BINARY ROLLBACK left this process reading a schema ahead of it. Package-level because
// it is determined during migration, before a Server exists — and exposed as a gauge because a fleet
// mid-rollback is a fleet-level question: a log line answers it per host, a metric answers it for the
// deployment, which is what is actually being asked during an upgrade.
var SchemaSkew atomic.Int64
