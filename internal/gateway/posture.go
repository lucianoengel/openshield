package gateway

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"sync/atomic"

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

// PostureSubscriber applies SIGNED posture updates to the store (SEC-1/D92). Posture is
// meant to be reported by the endpoint AGENT and signed with its key; the subscriber
// verifies each update against the trusted publisher key BEFORE applying it, so anyone who
// can merely publish to the posture subject cannot forge Compliant=true for any subject —
// which would defeat the D85 device-posture tamper-lockout, the security core of ZT. An
// update that does not verify is DROPPED and COUNTED, never applied.
//
// (The signed posture PRODUCER is HON-4 — until it exists this channel receives no valid
// update; the happy path is tested when the producer lands. What this fix guarantees NOW is
// that an UNSIGNED or forged posture update is rejected, closing the SEC-1 forgery hole.)
type PostureSubscriber struct {
	store      *PostureStore
	trustedPub ed25519.PublicKey
	Rejected   atomic.Int64
}

// NewPostureSubscriber builds a subscriber that verifies against the trusted posture key.
func NewPostureSubscriber(store *PostureStore, trustedPub ed25519.PublicKey) *PostureSubscriber {
	return &PostureSubscriber{store: store, trustedPub: trustedPub}
}

// Apply verifies a signed posture update and records it. A malformed, unsigned, wrong-key,
// or tampered update is an error — never a silent no-op (SEC-1). Verification happens BEFORE
// the inner PostureUpdate is parsed.
func (p *PostureSubscriber) Apply(data []byte) error {
	payload, err := verifySignedUpdate(data, p.trustedPub)
	if err != nil {
		return err
	}
	var pu corev1.PostureUpdate
	if err := proto.Unmarshal(payload, &pu); err != nil {
		return fmt.Errorf("gateway: bad posture update: %w", err)
	}
	if pu.GetSubject() == "" {
		return fmt.Errorf("gateway: posture update has no subject")
	}
	p.store.Set(pu.GetSubject(), core.DevicePosture{
		Compliant:     pu.GetCompliant(),
		DiskEncrypted: pu.GetDiskEncrypted(),
		AgentPresent:  pu.GetAgentPresent(),
		OSPatchTier:   core.PatchTier(pu.GetOsPatchTier()),
	})
	return nil
}

// Subscribe wires the subscriber to the posture subject; an update that fails verification
// is dropped and counted, so a forged-posture flood is observable, not silent.
func (p *PostureSubscriber) Subscribe(conn *nats.Conn) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectPosture, func(m *nats.Msg) {
		if err := p.Apply(m.Data); err != nil {
			p.Rejected.Add(1)
		}
	})
}
