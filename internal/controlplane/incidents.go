package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
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
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO incidents (subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen)
			 VALUES ($1,'open',$2,$3,$4,$5,$6)
			 ON CONFLICT (subject_id) WHERE state = 'open'
			 DO UPDATE SET alert_count = EXCLUDED.alert_count, max_risk = EXCLUDED.max_risk,
			              host_count = EXCLUDED.host_count, last_seen = EXCLUDED.last_seen,
			              first_seen = LEAST(incidents.first_seen, EXCLUDED.first_seen), updated_at = now()`,
			inc.SubjectID, inc.AlertCount, inc.MaxRisk, inc.HostCount, inc.FirstSeen, inc.LastSeen); err != nil {
			return 0, err
		}
	}
	return len(incidents), nil
}

// RecentIncidents returns materialized incidents, most recently active first.
func (s *Server) RecentIncidents(ctx context.Context, limit int) ([]StoredIncident, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, subject_id, state, alert_count, max_risk, host_count, first_seen, last_seen,
		        acknowledged_by, acknowledged_at
		   FROM incidents ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredIncident
	for rows.Next() {
		var i StoredIncident
		if err := rows.Scan(&i.ID, &i.SubjectID, &i.State, &i.AlertCount, &i.MaxRisk, &i.HostCount,
			&i.FirstSeen, &i.LastSeen, &i.AcknowledgedBy, &i.AcknowledgedAt); err != nil {
			return nil, err
		}
		i.Severity = Severity(i.MaxRisk)
		out = append(out, i)
	}
	return out, rows.Err()
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
	operator := operatorIdentity(r.TLS)
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
