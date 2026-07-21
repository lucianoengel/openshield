package gateway

import (
	"fmt"
	"sync"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// PostureStore holds the latest published device posture per subject (D92). The
// endpoint agent reports its device state; the gateway reads it here, and a subject
// with NO entry has NO posture — the D85 tamper-lockout: a killed/tampered endpoint
// reports no posture and the access policy denies it (absent posture fails CLOSED).
type PostureStore struct {
	mu      sync.RWMutex
	posture map[string]core.DevicePosture
}

func NewPostureStore() *PostureStore { return &PostureStore{posture: map[string]core.DevicePosture{}} }

// Set records a subject's latest posture. HasPosture is set true — the presence of an
// entry means posture WAS computed (distinct from absent, which fails closed, D85).
func (p *PostureStore) Set(subject string, dp core.DevicePosture) {
	dp.HasPosture = true
	p.mu.Lock()
	defer p.mu.Unlock()
	p.posture[subject] = dp
}

// Get returns the subject's posture, or has=false when none was published (untrusted).
func (p *PostureStore) Get(subject string) (core.DevicePosture, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	dp, ok := p.posture[subject]
	return dp, ok
}

// ApplyPostureUpdate decodes a published PostureUpdate into the store (D92). A
// malformed payload or empty subject is an error, never a silent no-op.
func ApplyPostureUpdate(data []byte, store *PostureStore) error {
	var pu corev1.PostureUpdate
	if err := proto.Unmarshal(data, &pu); err != nil {
		return fmt.Errorf("gateway: bad posture update: %w", err)
	}
	if pu.GetSubject() == "" {
		return fmt.Errorf("gateway: posture update has no subject")
	}
	store.Set(pu.GetSubject(), core.DevicePosture{
		Compliant:     pu.GetCompliant(),
		DiskEncrypted: pu.GetDiskEncrypted(),
		AgentPresent:  pu.GetAgentPresent(),
		OSPatchTier:   core.PatchTier(pu.GetOsPatchTier()),
	})
	return nil
}

// SubscribePosture subscribes the gateway to published posture updates.
func SubscribePosture(conn *nats.Conn, store *PostureStore) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectPosture, func(m *nats.Msg) {
		_ = ApplyPostureUpdate(m.Data, store)
	})
}
