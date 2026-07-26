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

// AlertRecord is what a detector hands RecordUnifiedAlert. It is a struct rather than a parameter list
// because the list had already reached seven same-typed strings, where transposing two (severity and
// title, subject and dedup key) compiles cleanly and silently writes a wrong alert; XDR-5's evidence
// references would have made it nine.
type AlertRecord struct {
	Domain      string // ueba | dlp | hips | nips | ...
	SubjectKind string // the entity alias kind to key by when the subject is new
	Subject     string
	Severity    string
	Title       string
	DedupKey    string // detector-namespaced idempotency key
	DetectedAt  time.Time

	// EventID / DecisionID are the EVIDENCE REFERENCE (XDR-5): what produced this alert, so an incident
	// timeline can reach the evidence behind it. BOTH EMPTY IS MEANINGFUL, not missing — a server-side
	// derivation (peer-UEBA) has no originating endpoint event or decision, and the timeline reports that
	// as its own state rather than as a blank field.
	EventID    string
	DecisionID string
}

// RecordUnifiedAlert records a normalized alert keyed to the XDR entity graph (XDR-2). It resolves the
// subject to an entity via the graph — so the alert binds to the SAME entity the device/user model
// knows, making cross-domain grouping an entity JOIN rather than a string match — then inserts,
// deduplicated by DedupKey. An alert whose subject cannot be resolved is NOT written as an unkeyed row
// (it would be uncorrelatable): the failure is counted and the caller's own recording is unaffected.
func (s *Server) RecordUnifiedAlert(ctx context.Context, a AlertRecord) error {
	if s.graph == nil {
		s.UnifiedAlertFailures.Add(1)
		return fmt.Errorf("unified alert: no entity graph")
	}
	entityID, err := s.entityForSubject(ctx, a.SubjectKind, a.Subject)
	if err != nil {
		s.UnifiedAlertFailures.Add(1)
		return fmt.Errorf("unified alert: resolving entity for %s %q: %w", a.SubjectKind, a.Subject, err)
	}
	at := a.DetectedAt
	if at.IsZero() {
		at = s.now()
	}
	// Dedup on the detector-namespaced key so a re-detection is one row (not multiplied correlation
	// input). ON CONFLICT DO NOTHING is atomic — no read-then-write race.
	//
	// The evidence references go in as NULL when empty rather than as '': the timeline distinguishes
	// "no originating decision" (a server derivation) from "a decision we cannot resolve", and an empty
	// string would collapse that distinction into a value that looks like a reference.
	_, err = s.pool.Exec(ctx,
		`INSERT INTO unified_alerts (entity_id, domain, subject_id, severity, title, dedup_key, detected_at,
		                             event_id, decision_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),NULLIF($9,''))
		 ON CONFLICT (dedup_key) DO NOTHING`,
		entityID, a.Domain, a.Subject, a.Severity, a.Title, a.DedupKey, at.UTC(), a.EventID, a.DecisionID)
	if err != nil {
		s.UnifiedAlertFailures.Add(1)
		return fmt.Errorf("unified alert: insert: %w", err)
	}
	return nil
}

// entityForSubject keys a subject onto the entity the graph ALREADY knows for it, whatever alias kind
// registered it, and only falls back to resolve-or-create under the caller's kind when the subject is
// genuinely new. Shared by unified-alert keying and by the ingest-time graph population, so both name
// an asset the same way — one keying rule in the system, not two that can disagree.
//
// The fallback alone is not enough, and the difference is load-bearing. The gateway's access proxy
// authorizes on a verified USER identity (it links device⋈user, XDR-1-WIRE), so its events carry a user
// subject. Resolving that as a device would find no device alias, mint a SECOND alias holding a user
// value, and put every ZT detection on an entity of its own — the alerts would look correct and never
// group with the same host's endpoint alerts. Cross-domain correlation would silently lose a domain.
//
// Residual, deliberately out of scope here: if a user-subject event is ingested BEFORE the access proxy
// has linked device⋈user, the device alias is minted first and the later Link does not reclaim it. A
// canonical one-alias-per-value rule would close that, and needs the Event to carry its subject's kind
// — a contract change. Documented rather than half-fixed.
func (s *Server) entityForSubject(ctx context.Context, subjectKind, subject string) (int64, error) {
	if id, ok, err := s.graph.LookupAny(ctx, subject); err != nil {
		return 0, err
	} else if ok {
		return id, nil
	}
	return s.graph.Resolve(ctx, subjectKind, subject)
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

// recordDeviceUnifiedAlert is the best-effort helper a SERVER-SIDE detector calls to project its alert
// into the unified stream, keyed by the subject's DEVICE entity (XDR-2). Best-effort: a failure is
// counted (in RecordUnifiedAlert) but never propagated, so the detector's authoritative record stands.
//
// It carries NO evidence reference, deliberately: a server-side derivation (peer-UEBA) is computed here
// from a fleet baseline — there is no originating endpoint event or decision to point at. The timeline
// reports that as `derived` rather than as an unresolvable reference (XDR-5).
func (s *Server) recordDeviceUnifiedAlert(ctx context.Context, domain, subject, severity, title, dedupKey string, at time.Time) {
	if err := s.RecordUnifiedAlert(ctx, AlertRecord{
		Domain: domain, SubjectKind: xdr.KindDevice, Subject: subject,
		Severity: severity, Title: title, DedupKey: dedupKey, DetectedAt: at,
	}); err != nil {
		// Counted inside RecordUnifiedAlert; the derived projection is not the system of record.
		return
	}
}
