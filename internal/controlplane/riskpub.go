package controlplane

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// SetRiskSigner installs the control-plane key that signs published risk updates (SEC-1).
// Without it, PublishRisk cannot sign and does not publish — a risk update MUST be signed so
// the gateway can verify it came from the control plane, not a forging publisher.
func (s *Server) SetRiskSigner(priv ed25519.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.riskSigner = priv
}

// signRiskUpdate wraps a marshalled RiskUpdate in a SignedUpdate signed by the control-plane
// key. Mirrors the gateway's verify side (SEC-1).
func signRiskUpdate(payload []byte, priv ed25519.PrivateKey) ([]byte, error) {
	sig := ed25519.Sign(priv, payload)
	return proto.Marshal(&corev1.SignedUpdate{Payload: payload, Signature: sig})
}

// PublishRisk publishes a subject's current risk to the gateways (D91), so continuous
// verification (D89) decides on real risk. The server publishes DATA; the gateway's
// LOCAL policy decides — the server never commands (T2/D14). Best-effort: a publish
// failure is logged, never fatal (it must not break telemetry ingest). The channel is
// authenticated at the connection level by mTLS NATS (D55); per-message signing is a
// hardening follow-up.
func (s *Server) PublishRisk(ctx context.Context, subject string, score float64) {
	s.mu.Lock()
	conn := s.conn
	signer := s.riskSigner
	s.mu.Unlock()
	if conn == nil {
		return
	}
	// SEC-1: a risk update MUST be signed, or the gateway would apply forged risk. Without
	// a signer, do not publish — an unsigned update the gateway would reject anyway.
	if signer == nil {
		fmt.Fprintf(os.Stderr, "openshield-server: risk publish skipped — no risk signer configured (SEC-1)\n")
		return
	}
	payload, err := proto.Marshal(&corev1.RiskUpdate{
		Subject: subject, RiskScore: score, ComputedAt: timestamppb.Now(),
	})
	if err != nil {
		return
	}
	data, err := signRiskUpdate(payload, signer)
	if err != nil {
		return
	}
	if err := conn.Publish(natsx.SubjectRisk, data); err != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: risk publish failed (subject recorded): %v\n", err)
	}
}
