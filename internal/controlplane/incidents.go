package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lucianoengel/openshield/internal/notify"
)

// ErrIncidentNotFound is returned when an ack targets an incident id that does not exist — distinct
// from "already acknowledged" (an idempotent no-op) and from a DB failure (which propagates).
var ErrIncidentNotFound = errors.New("controlplane: incident not found")

// StoredIncident is a materialized incident: a correlated incident with a stable id and lifecycle
// state, so it can be acknowledged or case-linked as a unit (SIEM-11b).
type StoredIncident struct {
	ID             int64      `json:"id"`
	SubjectID      string     `json:"subject_id"`
	State          string     `json:"state"`
	AlertCount     int        `json:"alert_count"`
	MaxRisk        float64    `json:"max_risk"`
	Severity       string     `json:"severity"`
	HostCount      int        `json:"host_count"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	// SOAR-2b: which incident this one recurs from (0 = none) and how many times the trouble has now
	// come back. Carried on the LIST response, not only the chain endpoint: an operator scanning
	// incidents needs to see "this is the fourth time" without asking a second question per row.
	RecurrenceOf    int64 `json:"recurrence_of,omitempty"`
	RecurrenceCount int   `json:"recurrence_count"`
	// Kind and RuleName say WHICH rule raised this incident (XDR-4c). The list already carried neither,
	// which was survivable while there was one burst rule and one cross-domain rule; with configured
	// hunts an asset can have several open cross-domain incidents at once, and without the rule they
	// are indistinguishable rows differing only in their counts. RuleName is empty for the burst rule
	// and for the unnamed cross-domain breadth rule — which is what those are, not a missing value.
	Kind     string `json:"kind,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
}

// MaterializeIncidents runs the correlation rule and persists each computed incident, upserting the
// subject's OPEN incident (one per subject): a re-correlated burst extends the open incident rather
// than duplicating it. Returns the number of incidents materialized. An acknowledged incident is
// left untouched — a new burst opens a fresh one only after the current is triaged.
func (s *Server) MaterializeIncidents(ctx context.Context, rule CorrelationRule, now time.Time) (int, error) {
	incidents, err := s.Correlate(ctx, rule, now)
	if err != nil {
		return 0, err
	}
	for _, inc := range incidents {
		// RETURNING (xmax = 0) tells us whether THIS upsert INSERTed a new incident (xmax is 0 on a
		// freshly-inserted row) or took the DO UPDATE path (xmax non-zero) that extends the subject's
		// open incident. SOAR-1 pages only on a genuine insert — a re-correlated burst updating the
		// open incident must not re-page.
		var id int64
		var inserted bool
		if err := s.pool.QueryRow(ctx,
			`INSERT INTO incidents (kind, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen, backfilled)
			 VALUES ('ueba_burst',$1,'open',$2,$3,$4,$5,$6,$7)
			 -- XDR-4c widened the open-incident index to (kind, rule_name, subject_id) so two named
			 -- hunts on one asset cannot collide. The burst rule has exactly one rule and always
			 -- writes rule_name '' (the column's default), so naming it here is what keeps this
			 -- conflict target matching an index — a mismatch is a runtime 42P10, not a compile error.
			 ON CONFLICT (kind, rule_name, subject_id) WHERE state = 'open'
			 DO UPDATE SET alert_count = EXCLUDED.alert_count, max_risk = EXCLUDED.max_risk,
			              host_count = EXCLUDED.host_count, last_seen = EXCLUDED.last_seen,
			              first_seen = LEAST(incidents.first_seen, EXCLUDED.first_seen), updated_at = now()
			 RETURNING id, (xmax = 0) AS inserted`,
			inc.SubjectID, inc.AlertCount, inc.MaxRisk, inc.HostCount, inc.FirstSeen, inc.LastSeen,
			s.quiet()).
			Scan(&id, &inserted); err != nil {
			return 0, err
		}
		if inserted {
			// SOAR-10: a backfilled incident is recorded and NOT paged. A month of backfill would page
			// the SOC for hundreds of incidents that are long over, at which point the pager is muted
			// and the next live incident is muted with it.
			if s.quiet() {
				continue
			}
			// SOAR-2b: link to the predecessor BEFORE paging, so the page can say "this is the third
			// time" rather than leaving the operator to discover it. A link failure degrades to an
			// unlinked incident and the materialization continues — strictly what we had before.
			//
			// COUNTED THROUGH THE SHARED HELPER, because this runs inside RunCorrelationLoop's tick with
			// the loop's context: a clean rolling restart used to raise
			// `openshield_recurrence_link_failures_total`, whose published meaning is that an incident
			// "pages as first-time trouble when it is the fourth return of something a responder already
			// closed". It also had no log call at all, so the number moved with nothing explaining it.
			rec, err := s.linkRecurrence(ctx, id, "ueba_burst", inc.SubjectID, nil, rule.RecurrenceWindow, now)
			if err != nil {
				NoteTickErr(ctx, nil, "linking an incident to the one it recurs from failed",
					&RecurrenceLinkFailures, err, slog.String("kind", "ueba_burst"))
			}
			s.notifyIncident(ctx, id, inc, now, rec)
		}
	}
	return len(incidents), nil
}

// notifyIncident pages a human that a NEW incident was raised (SOAR-1). The id is derived from the
// incident id (not the content-window notifyID), so the same incident never pages twice — including
// across a restart or a redundant materialization — while a genuinely new incident for the same
// subject (raised after the previous one left the open state, hence a new autoincrement id) pages
// again. Delivery is best-effort and off-ingest (emit queues; a nil/absent sink is a no-op): a page
// never fails materialization — the incidents row is the record, the notification is an additive copy.
func (s *Server) notifyIncident(ctx context.Context, id int64, inc Incident, now time.Time, rec Recurrence) {
	s.emit(ctx, notify.Notification{
		Kind:      notify.KindIncident,
		Subject:   inc.SubjectID,
		RiskScore: inc.MaxRisk,
		At:        now,
		ID:        fmt.Sprintf("inc_%d", id),
		Detail: fmt.Sprintf("%s incident: %d alerts across %d host(s), peak risk %.2f%s",
			inc.Severity, inc.AlertCount, inc.HostCount, inc.MaxRisk, recurrenceSuffix(rec)),
	})
}

// recurrenceSuffix renders a recurrence for a human, and renders nothing at all for a first occurrence.
//
// It goes in the page rather than only in the API because the page is where the decision gets made. Two
// incidents that read identically get triaged identically, and "this came back 20 minutes after we
// closed it" is the single most useful sentence available at that moment.
func recurrenceSuffix(rec Recurrence) string {
	if rec.Count == 0 {
		return ""
	}
	return fmt.Sprintf(" — RECURRENCE #%d (incident %d, %s earlier)",
		rec.Count, rec.Of, rec.Since.Round(time.Minute))
}

// IncidentPage is one page of a keyset walk over incidents.
type IncidentPage struct {
	Rows    []StoredIncident `json:"rows"`
	HasMore bool             `json:"has_more"`
	// NextCursor is ABSENT on the last page, never empty — a value a client could mistake for a usable
	// one must be absent, or it will be sent back and an empty page rendered as a real one.
	NextCursor string `json:"next_cursor,omitempty"`
}

// RecentIncidents returns materialized incidents, most recently active first.
//
// Kept as the un-paginated view for callers that want the first page and nothing else, so they are
// unchanged and the two views cannot disagree about what a page contains.
func (s *Server) RecentIncidents(ctx context.Context, limit int) ([]StoredIncident, error) {
	page, err := s.RecentIncidentsPage(ctx, limit, "")
	if err != nil {
		return nil, err
	}
	return page.Rows, nil
}

// RecentIncidentsPage is the paginated read (CONSOLE-6b): the same list, plus whether more incidents
// exist and where to continue from.
//
// Bare parameters rather than a one-field IncidentFilter struct: AlertFilter and EventFilter exist
// because they already carried several constraints each, and a struct wrapping one int and one string
// is a type that only makes the call site longer.
//
// ⚠️ INCIDENTS ARE NOT APPEND-ONLY, and this walk is therefore weaker than the /events one in a way that
// is accepted and stated rather than hidden. MaterializeIncidents upserts an OPEN incident's last_seen,
// from this route's own handler and from the leader's background correlation loop. An open incident not
// yet reached can have its last_seen pushed ahead of the walk boundary, and a keyset walk only moves one
// direction from a fixed point — so that row is absent from the rest of THIS walk and resurfaces at the
// top of a fresh one.
//
// ⚠️ NARROWER THAN IT FIRST LOOKS, because the upsert is IDEMPOTENT. `last_seen = EXCLUDED.last_seen` is
// `max(detected_at)` over the subject's alerts in the window — no writer of this column ever uses now().
// So re-running MaterializeIncidents with no new alerts rewrites the value it already stored and moves
// nothing. The unconditional materialization on every page of the walk therefore does NOT push every open
// incident above the boundary each time it is called; only an incident that actually absorbed a new alert
// moves. The residual is bounded by live detection, not by how deep the walk is — which is what makes
// accepting it reasonable rather than merely convenient.
//
// Bounded to state='open' as well: once acknowledged, the upsert's WHERE state='open'
// conflict target stops matching and a later burst opens a NEW row, so triaged history — which is what a
// deep walk exists to read — behaves exactly like /events. A snapshot is deliberately not built here;
// CONSOLE-6 ruled one out of scope for all keyset pagination, and building one only for incidents would
// contradict the precedent this extends.
func (s *Server) RecentIncidentsPage(ctx context.Context, limit int, cursor string) (IncidentPage, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit
	}
	q := `SELECT id, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen,
	             acknowledged_by, acknowledged_at, COALESCE(recurrence_of, 0), recurrence_count,
	             kind, rule_name
	        FROM incidents`
	args := []any{}
	// THE KEYSET BOUNDARY. Row-wise comparison against the exact ORDER BY tuple. `id` is half the key
	// because last_seen alone is not unique: it is `max(detected_at)` over the subject's alerts, so any
	// two subjects whose newest alert landed in the same detector pass tie exactly. A boundary on the
	// timestamp alone would step past the whole tied group and lose every row in it for the rest of the
	// walk. (An earlier version of this comment said a materialization pass stamps `now()` on every row
	// it touches. It does not — see RecentIncidentsPage's note. The tiebreaker is required either way,
	// and the tie fixture in the tests is a real tie, but the reason had to be the true one.)
	if cursor != "" {
		c, err := decodeIncidentCursor(cursor)
		if err != nil {
			return IncidentPage{}, err
		}
		args = append(args, c.LastSeen, c.ID)
		q += " WHERE (last_seen, id) < ($1, $2)"
	}
	// OVER-READ BY ONE to learn whether another page exists, rather than a second COUNT(*) pass that
	// would already be stale by the time the page rendered.
	args = append(args, limit+1)
	q += fmt.Sprintf(" ORDER BY last_seen DESC, id DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return IncidentPage{}, err
	}
	defer rows.Close()
	var out []StoredIncident
	for rows.Next() {
		var i StoredIncident
		if err := rows.Scan(&i.ID, &i.SubjectID, &i.State, &i.AlertCount, &i.MaxRisk, &i.HostCount,
			&i.FirstSeen, &i.LastSeen, &i.AcknowledgedBy, &i.AcknowledgedAt,
			&i.RecurrenceOf, &i.RecurrenceCount, &i.Kind, &i.RuleName); err != nil {
			return IncidentPage{}, err
		}
		i.Severity = Severity(i.MaxRisk)
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return IncidentPage{}, err
	}

	page := IncidentPage{Rows: out}
	if len(out) > limit {
		// The probe row is DISCARDED so `limit` means what it says, and the cursor comes from the last
		// RETURNED row — from the probe it would skip that row on the next page.
		page.Rows = out[:limit]
		page.HasMore = true
		last := page.Rows[limit-1]
		page.NextCursor = incidentCursor{LastSeen: last.LastSeen, ID: last.ID}.encode()
	}
	if page.Rows == nil {
		page.Rows = []StoredIncident{} // never `null`: an empty page and a failed read must not look alike
	}
	return page, nil
}

// AcknowledgeIncident marks an incident acknowledged by the (verified) operator. First-ack-wins (the
// state='open' guard preserves the original triager); a non-existent id is ErrIncidentNotFound, and
// a DB failure propagates rather than masquerading as not-found (SEC-11).
func (s *Server) AcknowledgeIncident(ctx context.Context, id int64, operator string) (newlyAcked bool, err error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE incidents SET state = 'acknowledged', acknowledged_by = $1, acknowledged_at = now(), updated_at = now()
		  WHERE id = $2 AND state = 'open'`, operator, id)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	var exists bool
	err = s.pool.QueryRow(ctx, `SELECT true FROM incidents WHERE id = $1`, id).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrIncidentNotFound
	}
	if err != nil {
		return false, err
	}
	return false, nil // exists but already acknowledged — idempotent no-op
}

// incidentAckHandler serves POST /incidents/ack?id=N, operator taken from the verified client cert.
func (s *Server) incidentAckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	operator := operatorIdentity(r.Context())
	if operator == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad or missing id", http.StatusBadRequest)
		return
	}
	newly, err := s.AcknowledgeIncident(r.Context(), id, operator)
	if err != nil {
		if errors.Is(err, ErrIncidentNotFound) {
			http.Error(w, "no such incident", http.StatusNotFound)
			return
		}
		http.Error(w, "ack failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"id": id, "state": "acknowledged", "newly_acknowledged": newly, "by": operator})
}
