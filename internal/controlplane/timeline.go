package controlplane

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// The cross-domain incident timeline (XDR-5). XDR-4 raises an incident that says "4 alerts across 3
// domains" and discards which alerts those were; this is the record of what an incident is MADE of, in
// detection order across domains, with a link from each alert to the evidence behind it.

// ErrNoTimelineForKind is returned for an incident kind that has no unified-alert join. A single-domain
// burst incident correlates peer_alerts by subject, so it has nothing to list — and an EMPTY timeline
// would read as "nothing contributed to this incident", which is false. An investigation surface must not
// return a quietly-wrong answer.
var ErrNoTimelineForKind = errors.New("controlplane: this incident kind has no alert timeline")

// Evidence resolution states. The distinction is load-bearing, not cosmetic: the per-agent
// forward-secure ledger is a DIFFERENT TRUST DOMAIN from the fleet aggregate (D30), so "the ledger entry
// is not in the database we can read" is the NORMAL case for a fleet deployment — not an anomaly, and not
// something to hide by dropping the row.
const (
	// EvidenceResolved: the referenced decision was found in the audit ledger, and the entry reports
	// that ledger entry's coordinates. It is a REACHABILITY fact, NOT a verification result — see
	// TimelineEntry.LedgerHash.
	EvidenceResolved = "resolved"
	// EvidenceUnresolved: the alert carries a reference, but no ledger row for it is reachable from this
	// database. The reference is returned intact and the entry is still listed. This is NOT evidence of
	// tampering — most often the agent's ledger simply lives elsewhere.
	EvidenceUnresolved = "unresolved"
	// EvidenceDerived: the alert is a server-side derivation (peer-UEBA) with no originating endpoint
	// event or decision at all. Distinct from unresolved: there is nothing to resolve, and saying so is
	// more honest than showing empty reference fields.
	EvidenceDerived = "derived"
)

// TimelineEntry is one contributing alert in an incident's timeline.
type TimelineEntry struct {
	AlertID    int64     `json:"alert_id"`
	Domain     string    `json:"domain"`
	Severity   string    `json:"severity"`
	SubjectID  string    `json:"subject_id"`
	Title      string    `json:"title"`
	DetectedAt time.Time `json:"detected_at"`

	// The evidence reference, as recorded on the alert (XDR-5). Empty on a server derivation.
	EventID    string `json:"event_id,omitempty"`
	DecisionID string `json:"decision_id,omitempty"`

	// Evidence is one of EvidenceResolved / EvidenceUnresolved / EvidenceDerived.
	Evidence string `json:"evidence"`
	// LedgerSequence / LedgerHash are the COORDINATES of the referenced ledger entry, present only when
	// Evidence == EvidenceResolved.
	//
	// They are NOT a verification result. Nothing here re-walks or re-verifies the hash chain — that is
	// the anchor binary's job — so a reported hash means "this is the entry we point at", never "we
	// proved this entry is intact". Naming or presenting it as verification would be an overclaim of
	// exactly the kind this project's honesty constraints exist to prevent.
	LedgerSequence int64  `json:"ledger_sequence,omitempty"`
	LedgerHash     string `json:"ledger_hash,omitempty"` // hex of the entry's hash
}

// IncidentTimeline returns an incident's contributing alerts in DETECTION order across domains, each with
// its evidence reference resolved against the audit ledger.
//
// Ordering is by detected_at, never by alert id: ids are control-plane INSERTION order, which for a
// spooled agent reconnecting after an outage bears no relation to when the detections happened — and the
// cross-domain interleaving is the entire point of a timeline.
func (s *Server) IncidentTimeline(ctx context.Context, incidentID int64) ([]TimelineEntry, error) {
	var kind string
	err := s.pool.QueryRow(ctx, `SELECT kind FROM incidents WHERE id = $1`, incidentID).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, err
	}
	if kind != IncidentKindCrossDomain {
		return nil, ErrNoTimelineForKind
	}

	rows, err := s.pool.Query(ctx,
		`SELECT a.id, a.domain, a.severity, a.subject_id, a.title, a.detected_at,
		        coalesce(a.event_id,''), coalesce(a.decision_id,'')
		   FROM incident_alerts ia
		   JOIN unified_alerts a ON a.id = ia.alert_id
		  WHERE ia.incident_id = $1
		  ORDER BY a.detected_at, a.id`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelineEntry
	for rows.Next() {
		var e TimelineEntry
		if err := rows.Scan(&e.AlertID, &e.Domain, &e.Severity, &e.SubjectID, &e.Title,
			&e.DetectedAt, &e.EventID, &e.DecisionID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.resolveEvidence(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// resolveEvidence stamps each entry's evidence state, looking the referenced decisions up in the AUDIT
// LEDGER — and in nothing else.
//
// The tempting shortcut is to resolve from fleet_telemetry: the row is always there (the projection read
// it to build the alert in the first place), and it would make every entry look resolved. That is exactly
// the D30 confusion the project has refused for three review rounds — the aggregate is a queryable
// convenience, explicitly NOT the evidentiary record — so presenting it as the resolved evidence would
// make the timeline's strongest-looking claim its most misleading one. An entry with no reachable LEDGER
// row is marked unresolved and keeps its reference.
//
// One batched query, so a timeline costs two round trips regardless of its length.
func (s *Server) resolveEvidence(ctx context.Context, entries []TimelineEntry) error {
	ids := make([]string, 0, len(entries))
	for i := range entries {
		if entries[i].DecisionID == "" {
			// Nothing to resolve: a server-side derivation has no originating decision.
			entries[i].Evidence = EvidenceDerived
			continue
		}
		entries[i].Evidence = EvidenceUnresolved // until the ledger says otherwise
		ids = append(ids, entries[i].DecisionID)
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT decision_id, sequence, hash FROM audit_entries WHERE decision_id = ANY($1)`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	type coords struct {
		seq  int64
		hash []byte
	}
	found := map[string]coords{}
	for rows.Next() {
		var (
			id string
			c  coords
		)
		if err := rows.Scan(&id, &c.seq, &c.hash); err != nil {
			return err
		}
		found[id] = c
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range entries {
		if c, ok := found[entries[i].DecisionID]; ok {
			entries[i].Evidence = EvidenceResolved
			entries[i].LedgerSequence = c.seq
			entries[i].LedgerHash = hex.EncodeToString(c.hash)
		}
	}
	return nil
}

// incidentTimelineHandler serves GET /incidents/timeline?id=N.
//
// It RECORDS THE VIEW BEFORE SERVING, following the Server.View discipline (D20/L1): an attempted view is
// more worth recording than a failed read is worth hiding, and this endpoint hands out an incident's
// evidence references — it must not become a way to read them without leaving a trace.
func (s *Server) incidentTimelineHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	viewer := operatorIdentity(r.TLS)
	if viewer == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad or missing id", http.StatusBadRequest)
		return
	}
	// Record first, then read.
	if err := s.RecordView(r.Context(), viewer, "incident:"+strconv.FormatInt(id, 10), ""); err != nil {
		http.Error(w, "view could not be recorded", http.StatusInternalServerError)
		return
	}
	entries, err := s.IncidentTimeline(r.Context(), id)
	switch {
	case errors.Is(err, ErrIncidentNotFound):
		http.Error(w, "no such incident", http.StatusNotFound)
		return
	case errors.Is(err, ErrNoTimelineForKind):
		// An explicit refusal, not an empty list: this incident kind correlates a single domain's alerts
		// by subject and has no contributing-alert join, so "[]" would read as "nothing contributed".
		http.Error(w, "no timeline for this incident kind: only cross-domain incidents carry a "+
			"contributing-alert timeline", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []TimelineEntry{}
	}
	writeJSON(w, entries)
}
