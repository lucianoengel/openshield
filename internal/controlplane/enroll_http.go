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
		mux.Handle("/view", requireTier(RoleAdmin, s.ViewHandler()))
		opRead := s.OperatorReadHandler() // one inner mux; the outer mount applies the tier gate per route
		mux.Handle("/alerts", requireTier(RoleAnalyst, opRead))
		mux.Handle("/alerts/ack", requireTier(RoleResponder, opRead)) // SIEM-6: acknowledge an alert (POST)
		mux.Handle("/search", requireTier(RoleAnalyst, opRead))
		mux.Handle("/events", requireTier(RoleAnalyst, opRead)) // SIEM-1: event search over the fleet aggregate
		mux.Handle("/logs", requireTier(RoleAnalyst, opRead))  // SIEM-4: search ingested third-party external logs
		mux.Handle("/compliance/retention", requireTier(RoleAnalyst, opRead)) // SIEM-10: retention compliance report
		mux.Handle("/incidents", requireTier(RoleAnalyst, opRead))
		mux.Handle("/incidents/ack", requireTier(RoleResponder, opRead)) // SIEM-11b: acknowledge an incident (POST)
		mux.Handle("/overdue", requireTier(RoleAnalyst, opRead))
		mux.Handle("/subject", requireTier(RoleAnalyst, opRead)) // PLAT-8: DSAR — compile what the platform holds about a subject
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
