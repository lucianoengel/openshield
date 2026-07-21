package controlplane

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// Correlation / rules engine (Phase F2). Peer-UEBA (D54) produces individual alerts; a
// SIEM's job is to correlate them into INCIDENTS a human acts on. This is the first rule:
// a BURST — the same pseudonymous subject tripping several alerts within a window is a
// stronger signal than any single alert. It correlates the fleet-derivation aggregate
// (peer_alerts), which is content-free and pseudonymous (D23/D54); no evidence is read.
//
// Cross-host correlation (the same subject on multiple agents) is a follow-up: peer_alerts
// records the subject and time but not the originating host, so temporal-by-subject is the
// correlation the current aggregate supports; a host column would add the cross-host facet.

// CorrelationRule parameterizes the burst rule. All fields have safe defaults.
type CorrelationRule struct {
	Window    time.Duration // look-back window (default 1h)
	MinAlerts int           // alerts within the window to raise an incident (default 3)
	MinRisk   float64       // ignore alerts below this risk (default 0)
}

// Incident is a correlated group of alerts for one subject — what an operator triages.
type Incident struct {
	SubjectID  string    `json:"subject_id"`
	AlertCount int       `json:"alert_count"`
	MaxRisk    float64   `json:"max_risk"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Correlate runs the burst rule and returns incidents, highest risk first. The window is
// applied as a cutoff computed from `now`, bound as a parameter (operator input is DATA);
// the HAVING threshold is what turns a scatter of alerts into an incident.
func (s *Server) Correlate(ctx context.Context, rule CorrelationRule, now time.Time) ([]Incident, error) {
	window := rule.Window
	if window <= 0 {
		window = time.Hour
	}
	minAlerts := rule.MinAlerts
	if minAlerts <= 0 {
		minAlerts = 3
	}
	cutoff := now.Add(-window)

	rows, err := s.pool.Query(ctx,
		`SELECT subject_id, count(*), max(risk_score), min(detected_at), max(detected_at)
		   FROM peer_alerts
		  WHERE risk_score >= $1 AND detected_at >= $2
		  GROUP BY subject_id
		 HAVING count(*) >= $3
		  ORDER BY max(risk_score) DESC`, rule.MinRisk, cutoff, minAlerts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var i Incident
		if err := rows.Scan(&i.SubjectID, &i.AlertCount, &i.MaxRisk, &i.FirstSeen, &i.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// incidentsHandler serves GET /incidents — the correlation rule over the fleet aggregate.
func (s *Server) incidentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rule := CorrelationRule{MinAlerts: queryInt(r, "min_alerts", 3)}
	if v := r.URL.Query().Get("window"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			rule.Window = d
		}
	}
	if v := r.URL.Query().Get("min_risk"); v != "" {
		if x, err := strconv.ParseFloat(v, 64); err == nil {
			rule.MinRisk = x
		}
	}
	incidents, err := s.Correlate(r.Context(), rule, time.Now())
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, incidents)
}
