package gateway

import (
	"fmt"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// ApplyRiskUpdate decodes a published RiskUpdate and records the subject's latest risk
// into the store (D91) — the gateway READS published risk; the LOCAL policy decides
// (D89, the T2 model). A malformed payload is an error, never a silent no-op.
func ApplyRiskUpdate(data []byte, store *RiskStore) error {
	var ru corev1.RiskUpdate
	if err := proto.Unmarshal(data, &ru); err != nil {
		return fmt.Errorf("gateway: bad risk update: %w", err)
	}
	if ru.GetSubject() == "" {
		return fmt.Errorf("gateway: risk update has no subject")
	}
	store.Set(ru.GetSubject(), ru.GetRiskScore())
	return nil
}

// SubscribeRisk subscribes the gateway to published risk updates and applies each to
// the store, so continuous verification (D89) decides on real risk. The subscription
// rides the same (mTLS-securable, D55) NATS the fleet uses.
func SubscribeRisk(conn *nats.Conn, store *RiskStore) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectRisk, func(m *nats.Msg) {
		_ = ApplyRiskUpdate(m.Data, store)
	})
}
