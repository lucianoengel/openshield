package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Correlation / rules engine (Phase F2). Peer-UEBA (D54) produces individual alerts; a
// SIEM's job is to correlate them into INCIDENTS a human acts on. This is the first rule:
// a BURST — the same pseudonymous subject tripping several alerts within a window is a
// stronger signal than any single alert. It correlates the fleet-derivation aggregate
// (peer_alerts), which is content-free and pseudonymous (D23/D54); no evidence is read.
//
// SIEM-2 adds the CROSS-HOST facet: each alert now records the verified agent that triggered
// it (D131), so the rule can count DISTINCT originating hosts. One subject anomalous across
// several agents (lateral movement, a shared credential) is a stronger, qualitatively
// different signal than a burst on a single host — an operator selects it with MinHosts.

// CorrelationRule parameterizes the burst rule. All fields have safe defaults.
type CorrelationRule struct {
	Window    time.Duration // look-back window (default 1h)
	MinAlerts int           // alerts within the window to raise an incident (default 3)
	MinRisk   float64       // ignore alerts below this risk (default 0)
	MinHosts  int           // distinct originating agents to raise an incident (default 1 = no cross-host constraint)
}

// Incident is a correlated group of alerts for one subject — what an operator triages.
type Incident struct {
	SubjectID  string    `json:"subject_id"`
	AlertCount int       `json:"alert_count"`
	MaxRisk    float64   `json:"max_risk"`
	Severity   string    `json:"severity"`   // triage bucket derived from MaxRisk (SIEM-6)
	HostCount  int       `json:"host_count"` // distinct agents the alerts came from (SIEM-2)
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
	minHosts := rule.MinHosts
	if minHosts <= 0 {
		minHosts = 1 // a group always has >= 1 agent id, so this is a no-op: plain burst semantics
	}
	cutoff := now.Add(-window)

	rows, err := s.pool.Query(ctx,
		`SELECT subject_id, count(*), max(risk_score), count(DISTINCT NULLIF(agent_id, '')), min(detected_at), max(detected_at)
		   FROM peer_alerts
		  WHERE risk_score >= $1 AND detected_at >= $2
		  GROUP BY subject_id
		 HAVING count(*) >= $3 AND count(DISTINCT NULLIF(agent_id, '')) >= $4
		  ORDER BY max(risk_score) DESC`, rule.MinRisk, cutoff, minAlerts, minHosts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var i Incident
		if err := rows.Scan(&i.SubjectID, &i.AlertCount, &i.MaxRisk, &i.HostCount, &i.FirstSeen, &i.LastSeen); err != nil {
			return nil, err
		}
		i.Severity = Severity(i.MaxRisk)
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
	// SEC-8: a malformed correlation param is a 400, not a silent fall-back to the default — a
	// silently-ignored bad window/min_risk widens the result and looks authoritative.
	q := r.URL.Query()
	var rule CorrelationRule
	var err error
	if rule.MinAlerts, err = intParam(q, "min_alerts", 3); err != nil {
		http.Error(w, "bad min_alerts: "+err.Error(), http.StatusBadRequest)
		return
	}
	if rule.MinHosts, err = intParam(q, "min_hosts", 1); err != nil {
		http.Error(w, "bad min_hosts: "+err.Error(), http.StatusBadRequest)
		return
	}
	if v := q.Get("window"); v != "" {
		d, derr := time.ParseDuration(v)
		if derr != nil {
			http.Error(w, "bad window: "+derr.Error(), http.StatusBadRequest)
			return
		}
		rule.Window = d
	}
	if v := q.Get("min_risk"); v != "" {
		x, ferr := strconv.ParseFloat(v, 64)
		if ferr != nil {
			http.Error(w, "bad min_risk: "+ferr.Error(), http.StatusBadRequest)
			return
		}
		rule.MinRisk = x
	}
	// SIEM-11b: materialize the current correlation (an idempotent upsert of each subject's open
	// incident) so incidents carry a stable id + state, then return the stored set. This makes the
	// list acknowledgeable/case-linkable as units rather than a recomputed-every-GET view.
	if _, err := s.MaterializeIncidents(r.Context(), rule, time.Now()); err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	// SEC-8: a malformed limit is a 400, not a silent default — a silently-ignored bad limit returns a
	// truncated/defaulted list that looks authoritative (the same rule the correlation params above use).
	limit, err := intParam(q, "limit", 100)
	if err != nil {
		http.Error(w, "bad limit: "+err.Error(), http.StatusBadRequest)
		return
	}
	incidents, err := s.RecentIncidents(r.Context(), limit)
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, incidents)
}

// intParam reads a positive-integer query param, returning def when absent and an error when
// present-but-malformed or non-positive (SEC-8 fail-loud).
func intParam(q url.Values, key string, def int) (int, error) {
	v := q.Get(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%q is not a positive integer", v)
	}
	return n, nil
}
