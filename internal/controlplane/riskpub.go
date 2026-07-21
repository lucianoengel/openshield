package controlplane

import (
	"context"
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// PublishRisk publishes a subject's current risk to the gateways (D91), so continuous
// verification (D89) decides on real risk. The server publishes DATA; the gateway's
// LOCAL policy decides — the server never commands (T2/D14). Best-effort: a publish
// failure is logged, never fatal (it must not break telemetry ingest). The channel is
// authenticated at the connection level by mTLS NATS (D55); per-message signing is a
// hardening follow-up.
func (s *Server) PublishRisk(ctx context.Context, subject string, score float64) {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return
	}
	data, err := proto.Marshal(&corev1.RiskUpdate{
		Subject: subject, RiskScore: score, ComputedAt: timestamppb.Now(),
	})
	if err != nil {
		return
	}
	if err := conn.Publish(natsx.SubjectRisk, data); err != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: risk publish failed (subject recorded): %v\n", err)
	}
}
