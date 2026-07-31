package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// enrollRequest is the POST /enroll body.
type enrollRequest struct {
	Token     string `json:"token"`
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"` // base64 std
}

// EnrollHandler serves POST /enroll — the agent's network onboarding (D44 over
// the wire). It exposes ENROLLMENT only; token ISSUANCE is deliberately not a
// route (an unauthenticated mint endpoint would defeat the single-use model —
// a leaked endpoint cannot mint credentials).
//
// Production MUST front this with TLS: the token travels in the body. It is
// single-use and short-TTL, so interception has limited value, but TLS is
// required — a deployment/config step, not application logic.
func (s *Server) EnrollHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", s.handleEnroll)
	return mux
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}
	err = s.Enroll(r.Context(), req.Token, req.AgentID, ed25519.PublicKey(pub), time.Now())
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"enrolled": true})
	case errors.Is(err, ErrEnrollment):
		// GENERIC — does not reveal whether the token was unknown, expired or
		// used, which would help an attacker probe the token space.
		http.Error(w, "enrollment refused", http.StatusUnauthorized)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// ServeHTTP runs the enrollment endpoint in plaintext until the context is
// cancelled. For production use ServeHTTPTLS — the token travels in the body.
func (s *Server) ServeHTTP(ctx context.Context, addr string) error {
	return s.serve(ctx, addr, nil)
}

// ServeHTTPTLS runs the enrollment endpoint over MUTUAL TLS (D55): the server
// demands and verifies a CA-issued client certificate, so a peer without one is
// refused at the handshake, before any token is seen. There is no plaintext
// fallback — a failed handshake is a refusal, not a downgrade.
func (s *Server) ServeHTTPTLS(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	return s.serve(ctx, addr, tlsCfg)
}

func (s *Server) serve(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	// Route mounting depends on TLS. In PLAINTEXT (dev loop): only /enroll, ungated
	// — there is no cert and no role. Under MUTUAL TLS: both routes, each gated by
	// the verified certificate's ROLE (D58) — /enroll requires the agent role (an
	// operator cert cannot fake an agent onboarding) and /view requires the
	// operator role (an agent cert cannot read investigations). The view route
	// exists only under TLS (D56).
	mux := http.NewServeMux()
	if tlsCfg != nil {
		mux.Handle("/enroll", requireRole(RoleAgent, s.EnrollHandler()))
		// PLAT-3/ADR-4: per-route RBAC tiers on the operator surface. The full investigation view is
		// the most sensitive read → admin; the read queue → analyst; the mutating acks → responder.
		// A higher tier satisfies a lower one, and a legacy `operator` cert ranks as admin (unchanged).
		mux.Handle("/view", s.requireTier(RoleAdmin, s.ViewHandler()))
		// SCIM (ZT-7): the identity provider's deprovisioning hook. NOT behind an operator tier — it
		// authenticates with its own token, because an operator credential that could reach it would let an
		// analyst deactivate an admin.
		mux.Handle(scimUsers, s.ScimHandler())
		mux.Handle(scimUsers+"/", s.ScimHandler())
		opRead := s.OperatorReadHandler() // one inner mux; the outer mount applies the tier gate per route
		mux.Handle("/alerts", s.requireTier(RoleAnalyst, opRead))
		mux.Handle("/alerts/ack", s.requireTier(RoleResponder, opRead)) // SIEM-6: acknowledge an alert (POST)
		mux.Handle("/search", s.requireTier(RoleAnalyst, opRead))
		mux.Handle("/events", s.requireTier(RoleAnalyst, opRead))      // SIEM-1: event search over the fleet aggregate
		mux.Handle("/logs", s.requireTier(RoleAnalyst, opRead))        // SIEM-4: search ingested third-party external logs
		mux.Handle("/logs/fields", s.requireTier(RoleAnalyst, opRead)) // SIEM-13: the cross-vendor vocabulary /logs accepts
		// SIEM-14: an analyst may list and run saved searches — they reach exactly the surfaces that
		// tier already reads, so allowing the run widens nothing. WRITING one is RESPONDER: a saved
		// search is a tool the whole team will run and trust, and its author is recorded.
		mux.Handle("/searches", s.requireTier(RoleAnalyst, opRead))
		mux.Handle("/searches/save", s.requireTier(RoleResponder, opRead))
		mux.Handle("/searches/run", s.requireTier(RoleAnalyst, opRead))
		mux.Handle("/searches/delete", s.requireTier(RoleResponder, opRead))
		mux.Handle("/compliance/retention", s.requireTier(RoleAnalyst, opRead)) // SIEM-10: retention compliance report
		mux.Handle("/incidents", s.requireTier(RoleAnalyst, opRead))
		mux.Handle("/incidents/ack", s.requireTier(RoleResponder, opRead))        // SIEM-11b: acknowledge an incident (POST)
		mux.Handle("/incidents/transition", s.requireTier(RoleResponder, opRead)) // SOAR-2: advance the lifecycle
		// XDR-5: an incident's contributing alerts + evidence references. Analyst tier — it is the drill-down
		// of the analyst's incident queue and carries no evidence CONTENT (only references and closed-
		// vocabulary metadata). Serving it records the view, so a read always leaves a trace (D20/L1).
		mux.Handle("/incidents/timeline", s.requireTier(RoleAnalyst, opRead))
		// SOAR-6's response report. It was registered on the inner operator mux and NEVER MOUNTED here,
		// so it has been unreachable over the only surface an operator connects on since it shipped —
		// the numbers were on /metrics and the JSON report answered 404 to everyone. Found by driving
		// it from the integration suite, which is the one place a route with no mount looks different
		// from a route that works.
		mux.Handle("/report/response", s.requireTier(RoleAnalyst, opRead))
		// SOAR-2b: the recurrence chain. Analyst tier alongside the timeline — it is the same
		// drill-down question asked across incidents instead of within one, and carries the same
		// closed-vocabulary metadata with no evidence content.
		mux.Handle("/incidents/recurrences", s.requireTier(RoleAnalyst, opRead))
		// SOAR-10: backfill correlates a historical range and WRITES incidents. ADMIN, not responder:
		// it is the only read-surface route that manufactures incidents in bulk, and a wide range is a
		// heavy job against the database the live pipeline is using.
		mux.Handle("/correlate/backfill", s.requireTier(RoleAdmin, opRead))
		mux.Handle("/overdue", s.requireTier(RoleAnalyst, opRead))
		mux.Handle("/subject", s.requireTier(RoleAnalyst, opRead)) // PLAT-8: DSAR — compile what the platform holds about a subject
		// D290: cases and approvals. Reading an investigation is the ANALYST tier and records the view
		// (D20); acting on one is RESPONDER. Releasing a legal hold is ADMIN — it is the only operation
		// here that makes evidence purgeable again, so it sits with the other destructive-adjacent act
		// rather than with case management.
		mux.Handle("/cases", s.requireTier(RoleAnalyst, opRead))
		mux.Handle("/cases/open", s.requireTier(RoleResponder, opRead))
		mux.Handle("/cases/assign", s.requireTier(RoleResponder, opRead))
		mux.Handle("/cases/note", s.requireTier(RoleResponder, opRead))
		mux.Handle("/cases/close/request", s.requireTier(RoleResponder, opRead))
		mux.Handle("/cases/close/approve", s.requireTier(RoleResponder, opRead))
		mux.Handle("/cases/hold/release", s.requireTier(RoleAdmin, opRead))
		mux.Handle("/approvals", s.requireTier(RoleAnalyst, opRead))
		mux.Handle("/approvals/resolve", s.requireTier(RoleResponder, opRead))
		// D291: response intents. RESPONDER for both steps — preparing one opens a four-eyes request in
		// someone's queue, which is an act, not a read. The four-eyes gate on CONTAIN and REVOKE_TRUST is
		// the control that separates them from the low-impact verb, not the route tier.
		mux.Handle("/intents/prepare", s.requireTier(RoleResponder, opRead))
		mux.Handle("/intents/publish", s.requireTier(RoleResponder, opRead))
		// D292: configuration. ADMIN for every route, including the reads: the effective view names every
		// host-level setting this deployment runs with, and the schema tells a reader exactly which knobs
		// exist to be turned. Changing configuration can disable detection, so it sits at the same tier
		// as the full investigation view rather than with the responder's actions.
		mux.Handle("/config", s.requireTier(RoleAdmin, opRead))
		mux.Handle("/config/schema", s.requireTier(RoleAdmin, opRead))
		mux.Handle("/config/revisions", s.requireTier(RoleAdmin, opRead))
		mux.Handle("/config/rollback", s.requireTier(RoleAdmin, opRead))
	} else {
		mux.Handle("/enroll", s.EnrollHandler())
	}
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, TLSConfig: tlsCfg}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	var err error
	if tlsCfg != nil {
		// Certs come from TLSConfig.Certificates, so the file args are empty.
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
