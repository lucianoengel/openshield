package gateway

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
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

// PostureSubscriber applies SIGNED posture updates to the store (D92). Posture is reported by the
// endpoint AGENT and signed with ITS OWN enrolled key; the subscriber verifies each update against
// the reporting agent's key — resolved by the update's subject (SEC-12) — BEFORE applying it. This
// closes both the unsigned/past-mTLS forgery (SEC-1) AND the agent-to-agent forgery a SHARED key
// left open: with one shared posture key, any agent could sign Compliant=true for ANOTHER agent and
// defeat the D85 tamper-lockout; binding subject↔key means an agent can only report its own posture.
// An update that does not verify is DROPPED and COUNTED, never applied.

// PostureKeyResolver returns the enrolled public key for a posture subject (the reporting agent),
// or ok=false if no such agent is enrolled. It binds subject↔key: an update is only applied for a
// subject if it verifies against THAT subject's own key.
type PostureKeyResolver func(subject string) (ed25519.PublicKey, bool)

type PostureSubscriber struct {
	store    *PostureStore
	keyFor   PostureKeyResolver
	Rejected atomic.Int64
}

// NewPostureSubscriber builds a subscriber that verifies each update against the REPORTING AGENT's
// own enrolled key (SEC-12), resolved by subject — so no agent can forge another's posture.
func NewPostureSubscriber(store *PostureStore, keyFor PostureKeyResolver) *PostureSubscriber {
	return &PostureSubscriber{store: store, keyFor: keyFor}
}

// Apply verifies a signed posture update against the reporting agent's OWN key and records it. A
// malformed, unsigned, unknown-subject, or wrong-key update is an error — never a silent no-op. The
// subject↔key binding (SEC-12) is the crux: the update is applied for subject S only if its
// signature verifies against S's enrolled key, so an agent holding only its own key cannot sign
// Compliant=true for a DIFFERENT subject (the shared-key forgery SEC-1 left open).
func (p *PostureSubscriber) Apply(data []byte) error {
	payload, sig, err := splitSignedUpdate(data)
	if err != nil {
		return err
	}
	var pu corev1.PostureUpdate
	if err := proto.Unmarshal(payload, &pu); err != nil {
		return fmt.Errorf("gateway: bad posture update: %w", err)
	}
	subject := pu.GetSubject()
	if subject == "" {
		return fmt.Errorf("gateway: posture update has no subject")
	}
	key, ok := p.keyFor(subject)
	if !ok {
		return fmt.Errorf("gateway: no enrolled key for posture subject %q", subject)
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, payload, sig) {
		return fmt.Errorf("gateway: posture update for %q does not verify against its own enrolled key", subject)
	}
	p.store.Set(subject, core.DevicePosture{
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

// LoadPostureRoster reads a posture-key roster from a file — one "<subject> <base64-ed25519-pubkey>"
// per line (blank lines and #-comments ignored) — and returns a resolver over it, so the gateway
// verifies each agent's posture against that agent's OWN enrolled key (SEC-12) instead of a single
// shared key. Distributing the roster to the gateway (exported from the control-plane enrollment
// records) is a deployment step; keeping it in sync automatically from the control plane is a follow-up.
func LoadPostureRoster(path string) (PostureKeyResolver, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	roster := map[string]ed25519.PublicKey{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("gateway: bad roster line %q (want '<subject> <base64-pubkey>')", line)
		}
		key, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("gateway: bad pubkey for %q in roster", fields[0])
		}
		roster[fields[0]] = ed25519.PublicKey(key)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(roster) == 0 {
		return nil, fmt.Errorf("gateway: posture roster %q is empty", path)
	}
	return func(subject string) (ed25519.PublicKey, bool) {
		k, ok := roster[subject]
		return k, ok
	}, nil
}
