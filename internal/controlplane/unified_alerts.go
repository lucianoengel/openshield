package controlplane

import (
	"context"
	"fmt"
	"time"

	"github.com/lucianoengel/openshield/internal/xdr"
)

// UnifiedAlert is one normalized, entity-keyed alert (XDR-2): a detection from any domain, bound to the
// XDR entity (device/user) it concerns, so a single correlation engine reads all domains from one
// stream. It is the projection the XDR-4 correlation layer consumes.
type UnifiedAlert struct {
	EntityID   int64
	Domain     string // which detection domain: ueba | dlp | hips | nips | zt | ...
	SubjectID  string
	Severity   string
	Title      string
	DedupKey   string
	Status     string
	DetectedAt time.Time
}

// RecordUnifiedAlert records a normalized alert keyed to the XDR entity graph (XDR-2). It resolves the
// subject to an entity via the graph — so the alert binds to the SAME entity the device/user model
// knows, making cross-domain grouping an entity JOIN rather than a string match — then inserts,
// deduplicated by dedupKey. An alert whose subject cannot be resolved is NOT written as an unkeyed row
// (it would be uncorrelatable): the failure is counted and the caller's own recording is unaffected.
func (s *Server) RecordUnifiedAlert(ctx context.Context, domain, subjectKind, subject, severity, title, dedupKey string, at time.Time) error {
	if s.graph == nil {
		s.UnifiedAlertFailures.Add(1)
		return fmt.Errorf("unified alert: no entity graph")
	}
	entityID, err := s.graph.Resolve(ctx, subjectKind, subject)
	if err != nil {
		s.UnifiedAlertFailures.Add(1)
		return fmt.Errorf("unified alert: resolving entity for %s %q: %w", subjectKind, subject, err)
	}
	if at.IsZero() {
		at = s.now()
	}
	// Dedup on the detector-namespaced key so a re-detection is one row (not multiplied correlation
	// input). ON CONFLICT DO NOTHING is atomic — no read-then-write race.
	_, err = s.pool.Exec(ctx,
		`INSERT INTO unified_alerts (entity_id, domain, subject_id, severity, title, dedup_key, detected_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (dedup_key) DO NOTHING`,
		entityID, domain, subject, severity, title, dedupKey, at.UTC())
	if err != nil {
		s.UnifiedAlertFailures.Add(1)
		return fmt.Errorf("unified alert: insert: %w", err)
	}
	return nil
}

// AlertsForEntity returns every domain's alerts for one entity, newest first — the cross-domain view a
// correlation engine (XDR-4) reads to find a multi-domain attack on one asset.
func (s *Server) AlertsForEntity(ctx context.Context, entityID int64) ([]UnifiedAlert, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT entity_id, domain, subject_id, severity, title, dedup_key, status, detected_at
		   FROM unified_alerts WHERE entity_id = $1 ORDER BY detected_at DESC, id DESC`, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UnifiedAlert
	for rows.Next() {
		var a UnifiedAlert
		if err := rows.Scan(&a.EntityID, &a.Domain, &a.SubjectID, &a.Severity, &a.Title,
			&a.DedupKey, &a.Status, &a.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// recordDeviceUnifiedAlert is the best-effort helper a server-side detector calls to project its alert
// into the unified stream, keyed by the subject's DEVICE entity (XDR-2). Best-effort: a failure is
// counted (in RecordUnifiedAlert) but never propagated, so the detector's authoritative record stands.
func (s *Server) recordDeviceUnifiedAlert(ctx context.Context, domain, subject, severity, title, dedupKey string, at time.Time) {
	if err := s.RecordUnifiedAlert(ctx, domain, xdr.KindDevice, subject, severity, title, dedupKey, at); err != nil {
		// Counted inside RecordUnifiedAlert; the derived projection is not the system of record.
		return
	}
}
