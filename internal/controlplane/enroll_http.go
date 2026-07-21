package controlplane

import (
	"context"
	"crypto/ed25519"
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

// ServeHTTP runs the enrollment endpoint until the context is cancelled, then
// shuts it down gracefully.
func (s *Server) ServeHTTP(ctx context.Context, addr string) error {
	srv := &http.Server{Addr: addr, Handler: s.EnrollHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
