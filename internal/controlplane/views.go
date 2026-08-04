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

// requireRole gates a handler on an EXACT role: 401 when there is no verified cert (unauthenticated), 403
// when the role in force is not the one required (authenticated but not authorized), else it serves h. The
// role comes from the certificate's identity, never the request (D58).
//
// AN EXACT-ROLE GATE IS ONLY USED FOR `agent`, which is not an operator tier and is not in the roles table
// (see parseGrant). So this deliberately still reads the certificate: an agent's role is a property
// of the credential the fleet was issued, not an operator grant somebody administers.
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

// requireTier gates a handler on a MINIMUM operator tier (PLAT-3/ADR-4): 401 when there is no verified
// cert, 403 when the role IN FORCE ranks below minRole, else it serves h. A higher tier satisfies a lower
// requirement (admin ≥ responder ≥ analyst). The role comes from the identity, never the request (D58).
func (s *Server) requireTier(minRole string, h http.Handler) http.Handler {
	return s.requireGrant(minRole, h)
}

// requirePrivacyOfficer gates a handler on the DATA-SUBJECT authority, which no tier satisfies —
// including admin (CONSOLE-1). Spelled as its own wrapper because `requireTier(RolePrivacyOfficer, …)`
// at a mount site would read as a claim about tiers, and it is the opposite of one.
func (s *Server) requirePrivacyOfficer(h http.Handler) http.Handler {
	return s.requireGrant(RolePrivacyOfficer, h)
}

// requireGrant is the gate both wrappers share: 401 with no credential, 403 when the grant in force does
// not satisfy `require`, else it serves h with the authenticated principal on the context.
//
// A METHOD, AND THAT IS THE ZT-7 CHANGE (D372). This used to be a package function reading the role out of
// the certificate's OU, which meant authorization was frozen for the certificate's lifetime: a demotion or
// a removal did not take effect until it expired, and there was no "revoke this operator's responder rights
// now" at all. It now resolves against the operator_roles table on every request — see
// resolveOperatorRole, including why there is no cache and why a database error denies rather than falling
// back to the certificate.
func (s *Server) requireGrant(require string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// AUTHENTICATE, then authorize. A client certificate or an OIDC bearer token (ZT-7); both converge
		// on the same server-side role.
		auth := s.authenticateOperator(r)
		if !auth.ok {
			http.Error(w, "client certificate or bearer token required", http.StatusUnauthorized)
			return
		}
		grant, src := s.resolveOperatorRole(r.Context(), auth)
		if src == roleFromCertificate && grant.Tier != "" {
			s.warnLegacyRole(auth.principal.String(), grant.Tier)
		}
		if !grant.satisfies(require) {
			// The message distinguishes a REVOCATION from merely ranking too low, because those send an
			// operator to completely different places: one is "ask for access", the other is "your access
			// was taken away and you should know that".
			if src == roleRevoked {
				http.Error(w, "forbidden: this operator identity has been revoked", http.StatusForbidden)
				return
			}
			// A THIRD MESSAGE FOR THE PRIVACY AXIS, because "your tier is too low" is actively misleading
			// here: the admin refused at a privacy route holds the HIGHEST tier there is, and telling them
			// to ask for a higher one sends them to look for something that does not exist (CONSOLE-1).
			if require == RolePrivacyOfficer {
				http.Error(w, "forbidden: this endpoint is the privacy officer's, and no operator tier "+
					"grants it — including admin", http.StatusForbidden)
				return
			}
			http.Error(w, "forbidden: operator role tier not authorized for this endpoint", http.StatusForbidden)
			return
		}
		// THE AUTHENTICATED PRINCIPAL TRAVELS WITH THE REQUEST (CONSOLE-1).
		//
		// It used to be resolved here and dropped, and eight handlers re-derived an identity from the TLS
		// peer certificate — which is absent for a bearer-authenticated operator. So SSO passed this gate
		// and was then refused by every handler that needed to know WHO was calling. Authenticating twice,
		// by two different rules, is how those two answers came to disagree.
		h.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), auth.principal)))
	})
}

// principalCtxKey is unexported and of a private type, so nothing outside this package can put a
// principal on a context — the value a handler trusts must come from requireTier and nowhere else.
type principalCtxKey struct{}

// withPrincipal attaches the authenticated principal to a request context.
func withPrincipal(ctx context.Context, p operatorPrincipal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// principalFrom reads the authenticated principal, reporting false when there is none.
//
// A handler that reaches this with no principal is mounted outside requireTier, which is a wiring bug
// rather than an authorization decision — so it refuses, and does not attempt to re-derive an identity
// from the connection. Re-deriving is what CONSOLE-1 exists to remove.
func principalFrom(ctx context.Context) (operatorPrincipal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(operatorPrincipal)
	return p, ok && p.valid()
}

// operatorIdentity returns the authenticated principal's canonical string, or "" when the request
// carries none.
//
// It kept its name and lost its argument, which is the point: every call site used to pass `r.TLS` and
// therefore answered "" for a perfectly well-authenticated bearer request. The compiler found all eight.
func operatorIdentity(ctx context.Context) string {
	p, ok := principalFrom(ctx)
	if !ok {
		return ""
	}
	return p.String()
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
		viewer := operatorIdentity(r.Context())
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

// viewAuditHandler serves GET /views?event=<id> or ?viewer=<principal> — WHO LOOKED AT WHAT.
//
// This is the privacy officer's route, and it is the reason the split has teeth. The control plane has
// recorded every investigation view since D20/T-013, and until now NOTHING COULD READ IT: `Views` and
// `ViewsBy` had no caller anywhere outside their own tests. An accountability record nobody can read is
// a record that accounts to nobody — the same unwired shape this repo has now found in D313, D415, D417,
// D418 and CONSOLE-1's own `/report/response`.
//
// Gated on the privacy authority alone, deliberately: an administrator reading the log of who viewed
// what would be auditing themselves, and the tier that can look at investigations must not be the tier
// that reviews the looking.
//
// Reading it is itself recorded, like every other read of this surface. Nobody is above the record,
// including whoever holds this route.
func (s *Server) viewAuditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	officer := operatorIdentity(r.Context())
	if officer == "" {
		http.Error(w, "client certificate or bearer token required", http.StatusUnauthorized)
		return
	}
	event, viewer := r.URL.Query().Get("event"), r.URL.Query().Get("viewer")
	// EXACTLY ONE, and neither defaults to "everything". An unfiltered dump of the whole view log is a
	// different and much broader question than "who looked at this investigation", and it should be
	// asked for explicitly by whoever builds it rather than fallen into by omitting a parameter.
	if (event == "") == (viewer == "") {
		http.Error(w, "give exactly one of ?event= or ?viewer=", http.StatusBadRequest)
		return
	}
	if err := s.RecordView(r.Context(), officer, viewer, event); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var (
		records []ViewRecord
		err     error
	)
	if event != "" {
		records, err = s.Views(r.Context(), event)
	} else {
		records, err = s.ViewsBy(r.Context(), viewer)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(records))
	for _, v := range records {
		out = append(out, map[string]any{
			"viewer": v.Viewer, "subject_filter": v.SubjectFilter,
			"event_id": v.EventID, "viewed_at": v.ViewedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	writeJSON(w, map[string]any{"rows": out})
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
