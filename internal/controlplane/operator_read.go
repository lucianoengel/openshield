package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// PeerAlert is one server-side peer-UEBA detection, as an operator reads it. The
// subject is pseudonymous (D23) and there is no content — a peer alert is the
// control plane's own fleet-aggregate detection (D54), not evidence.
type PeerAlert struct {
	SubjectID      string    `json:"subject_id"`
	RiskScore      float64   `json:"risk_score"`
	ContextVersion string    `json:"context_version"`
	DetectedAt     time.Time `json:"detected_at"`
}

// RecentPeerAlerts returns the most recent peer alerts, newest first.
func (s *Server) RecentPeerAlerts(ctx context.Context, limit int) ([]PeerAlert, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT subject_id, risk_score, context_version, detected_at
		   FROM peer_alerts ORDER BY detected_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PeerAlert
	for rows.Next() {
		var a PeerAlert
		if err := rows.Scan(&a.SubjectID, &a.RiskScore, &a.ContextVersion, &a.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// OperatorReadHandler serves the operator's read surface over the fleet: recent peer
// alerts (/alerts) and overdue agents (/overdue). It is mounted behind the
// operator-role gate (D82); it holds no signer and can forge nothing (D30).
func (s *Server) OperatorReadHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		limit := queryInt(r, "limit", 100)
		alerts, err := s.RecentPeerAlerts(r.Context(), limit)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, alerts)
	})

	mux.HandleFunc("/overdue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		threshold := 15 * time.Minute
		if v := r.URL.Query().Get("threshold"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				threshold = d
			}
		}
		overdue, err := s.Overdue(r.Context(), threshold, time.Now())
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, overdue)
	})

	return mux
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
