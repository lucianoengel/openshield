package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrNoViewer is returned when a view is recorded without an identity — no
// unattributable view may be silently recorded (D20).
var ErrNoViewer = errors.New("controlplane: view requires a viewer identity")

// ViewRecord is one recorded investigation view.
type ViewRecord struct {
	Viewer        string
	SubjectFilter string
	EventID       string
	ViewedAt      time.Time
}

// RecordView writes that an investigation was viewed. The viewer must carry an
// identity — callers pass "unauthenticated:<os-user>" until operator
// authentication exists, so a self-asserted OS identity is never mistaken for a
// verified operator. It is NOT the evidentiary ledger (D41-style caveat).
func (s *Server) RecordView(ctx context.Context, viewer, subjectFilter, eventID string) error {
	if viewer == "" {
		return ErrNoViewer
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO investigation_views (viewer, subject_filter, event_id) VALUES ($1,$2,$3)`,
		viewer, subjectFilter, eventID)
	return err
}

// View serves an investigation AND records the view in one call, so a caller
// cannot obtain the evidence without leaving a record. The view is recorded
// FIRST — an attempted view is more worth recording than a failed read is worth
// hiding.
func (s *Server) View(ctx context.Context, viewer, eventID string) ([]TelemetryRow, error) {
	if viewer == "" {
		return nil, ErrNoViewer
	}
	if err := s.RecordView(ctx, viewer, "", eventID); err != nil {
		return nil, fmt.Errorf("controlplane: recording view: %w", err)
	}
	return s.TelemetryForEvent(ctx, eventID)
}

// Cert roles (D58): a verified client certificate carries a ROLE in its Subject
// Organizational Unit, and each mutual-TLS route authorizes by that role — not
// merely by the fact of a valid cert. Trust rests on the CA's issuance discipline
// (a CA that signs OU=operator for the wrong party loses, the PKI trust class);
// the win is that the role is CHECKED. A production system might use a dedicated
// policy OID instead of OU.
const (
	RoleAgent    = "agent"
	RoleOperator = "operator" // legacy full-access operator; ranks as admin (PLAT-3)
	// Operator tiers (PLAT-3/ADR-4), ordered analyst < responder < admin.
	RoleAnalyst   = "analyst"
	RoleResponder = "responder"
	RoleAdmin     = "admin"
)

// roleRank orders the operator tiers so a higher tier satisfies a lower requirement (PLAT-3/ADR-4).
// The legacy `operator` role ranks as admin (full access, backward compatible). `agent` and any
// unknown/absent role rank 0 — authorized for NO operator route (deny by default).
func roleRank(role string) int {
	switch role {
	case RoleAnalyst:
		return 1
	case RoleResponder:
		return 2
	case RoleAdmin, RoleOperator:
		return 3
	default:
		return 0
	}
}

// certRole returns the first recognised role in the verified peer certificate's
// OU, or "" (an unknown/absent role is authorized for nothing — deny by default).
func certRole(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	for _, ou := range state.PeerCertificates[0].Subject.OrganizationalUnit {
		switch ou {
		case RoleAgent, RoleOperator, RoleAnalyst, RoleResponder, RoleAdmin:
			return ou
		}
	}
	return ""
}

// requireRole gates a handler on the verified certificate's role: 401 when there
// is no verified cert (unauthenticated), 403 when the cert's role is not the one
// required (authenticated but not authorized), else it serves h. The role comes
// from the certificate, never the request (D58).
func requireRole(role string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if certRole(r.TLS) != role {
			// Authenticated, but this identity is not allowed here (403 ≠ 401).
			http.Error(w, "forbidden: certificate role not authorized for this endpoint", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// requireTier gates a handler on a MINIMUM operator tier (PLAT-3/ADR-4): 401 when there is no
// verified cert, 403 when the cert's role ranks BELOW minRole, else it serves h. A higher tier
// satisfies a lower requirement (admin ≥ responder ≥ analyst), and the legacy `operator` role ranks
// as admin so existing operator certificates keep full access. The role comes from the certificate,
// never the request (D58).
func requireTier(minRole string, h http.Handler) http.Handler {
	min := roleRank(minRole)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if roleRank(certRole(r.TLS)) < min {
			http.Error(w, "forbidden: certificate role tier not authorized for this endpoint", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// operatorIdentity derives the viewer identity from a VERIFIED mutual-TLS client
// certificate (D56). The handler runs only under RequireAndVerifyClientCert
// (D55), so a present peer certificate is already CA-verified — this reads the
// established identity, it does not re-verify. Returns "" when no peer
// certificate is present (checked defensively; the required-client-cert config
// makes this unreachable in production), which the caller turns into a refusal.
func operatorIdentity(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	return "operator:" + state.PeerCertificates[0].Subject.CommonName
}

// ViewHandler serves an authenticated investigation view (D56). It records the
// view under the identity taken from the client CERTIFICATE — never a
// caller-supplied name — and refuses a request with no verified certificate,
// so no unattributable view occurs (D20). The view is recorded before the
// evidence is returned (the View invariant). It is mounted ONLY under mutual TLS
// (there is no authenticated identity to record otherwise).
func (s *Server) ViewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/view", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		viewer := operatorIdentity(r.TLS)
		if viewer == "" {
			// No verified certificate → no accountable identity → no view (D20).
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		eventID := r.URL.Query().Get("event")
		if eventID == "" {
			http.Error(w, "missing event", http.StatusBadRequest)
			return
		}
		rows, err := s.View(r.Context(), viewer, eventID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Boundary-safe projection: event id + kind only, never payload content.
		out := make([]map[string]string, 0, len(rows))
		for _, row := range rows {
			out = append(out, map[string]string{"event_id": row.EventID, "kind": row.Kind})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"viewer": viewer, "rows": out})
	})
	return mux
}

// Views returns recorded views for an event, oldest first.
func (s *Server) Views(ctx context.Context, eventID string) ([]ViewRecord, error) {
	return s.viewQuery(ctx, `SELECT viewer, subject_filter, event_id, viewed_at
		FROM investigation_views WHERE event_id = $1 ORDER BY id ASC`, eventID)
}

// ViewsBy returns recorded views by a viewer, oldest first.
func (s *Server) ViewsBy(ctx context.Context, viewer string) ([]ViewRecord, error) {
	return s.viewQuery(ctx, `SELECT viewer, subject_filter, event_id, viewed_at
		FROM investigation_views WHERE viewer = $1 ORDER BY id ASC`, viewer)
}

func (s *Server) viewQuery(ctx context.Context, sql, arg string) ([]ViewRecord, error) {
	rows, err := s.pool.Query(ctx, sql, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ViewRecord
	for rows.Next() {
		var v ViewRecord
		if err := rows.Scan(&v.Viewer, &v.SubjectFilter, &v.EventID, &v.ViewedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
