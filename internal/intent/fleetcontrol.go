package intent

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// Fleet-wide operational control (PLAT-9): the endpoint half of "stop enforcing now".
//
// D265's kill switch reaches server-side components through the configuration store. ENDPOINT AGENTS DO
// NOT READ IT, so until this they were disabled only by a local break-glass file — a gap named when the
// switch shipped rather than left for someone to discover.
//
// THIS IS THE MOST ATTRACTIVE FORGERY TARGET IN THE SYSTEM: one accepted message turns the product off
// across a fleet. So it carries three independent bounds, and each answers a different attack:
//
//   - the SIGNATURE answers "who said this" (origin, not authority — a compromised control plane is
//     indistinguishable, which is why publication is separately four-eyes gated);
//   - a MONOTONIC SEQUENCE answers replay: a captured DISABLE cannot be re-sent after an operator
//     restored enforcement, because it is at or below the highest sequence already applied — and that
//     bound is PERSISTED (SEC-B), because a bound that resets on restart bounds nothing an attacker who
//     can wait cannot get around;
//   - MANDATORY EXPIRY answers duration: a captured or forgotten DISABLE cannot last, because a consumer
//     treats an expired control as absent.
//
// And it FAILS TOWARD ENFORCING, like the switch it drives: anything unverifiable, replayed, expired or
// of an unknown version changes nothing at all.

// ErrFleetVersion means the control carries a version this consumer does not understand. Rejected whole
// rather than partially applied — a message about turning the product off is the last one to guess at.
var ErrFleetVersion = errors.New("intent: unknown fleet-control version")

// Applier is what a verified control acts on — core.KillSwitch satisfies it. An interface so this package
// does not import the enforcement path it drives.
type Applier interface {
	Engage(reason, source string)
	Disengage(source string)
}

// FleetControlSubscriber verifies signed fleet controls and applies them.
type FleetControlSubscriber struct {
	// Key is the control-plane public key. A control that does not verify against it is not from the
	// control plane, and this message type disables the product.
	Key ed25519.PublicKey

	mu      sync.Mutex
	applied uint64 // the highest sequence applied — the replay bound
	bound   natsx.SeqStore
	target  Applier

	// Rejected counts controls dropped for a bad signature, an unknown version, a replay or expiry. A
	// forged-control flood must be observable, not silent.
	Rejected atomic.Int64
	// Applied counts controls that took effect.
	Applied atomic.Int64
}

// NewFleetControlSubscriber returns a subscriber whose replay bound is HELD IN MEMORY ONLY.
//
// That is a real limit and not a detail: a restart resets the bound to zero, so every control an
// attacker captured replays until its own expiry. Production wiring uses
// NewPersistentFleetControlSubscriber; this constructor exists for tests and for a deployment that
// explicitly accepts the window, and a binary that uses it must say so at startup (D31 — a gap must
// never be silent).
func NewFleetControlSubscriber(key ed25519.PublicKey, target Applier) *FleetControlSubscriber {
	return &FleetControlSubscriber{Key: key, target: target}
}

// NewPersistentFleetControlSubscriber returns a subscriber whose replay bound SURVIVES A RESTART
// (SEC-B).
//
// The bound is the whole of the replay defence, and until this it was a `uint64` struct field. The
// publisher's sequence has been persisted since D66 — precisely because "without it a restart replays
// sequence numbers" — but the CONSUMER is where a replay is refused, so persisting only the publisher's
// half left the refusal resetting to zero on every boot. `docs/threat-model.md` claimed the sequence was
// "stored rather than held in memory"; it was true of the publisher and false here.
//
// Two things happen at construction, and both are refusals rather than fallbacks:
//
//   - LOAD. A corrupt bound is an error, never a reset to 0 — resetting is exactly the state an attacker
//     wants, so a file we cannot read is a reason to refuse to start, not to start unbounded.
//   - PROBE. The loaded value is written straight back. It is a no-op semantically and it answers, at
//     startup, the question an operator would otherwise first ask during an incident: is this directory
//     actually writable by this process? Without the probe an unwritable path is discovered when the
//     first real control arrives, and that control is refused (see apply) — a fleet-wide disable failing
//     at the moment it is needed, for a reason that was knowable at boot.
func NewPersistentFleetControlSubscriber(key ed25519.PublicKey, target Applier,
	bound natsx.SeqStore) (*FleetControlSubscriber, error) {
	if bound == nil {
		return nil, errors.New("intent: no replay bound supplied; use NewFleetControlSubscriber to " +
			"accept an in-memory bound deliberately")
	}
	applied, err := bound.Load()
	if err != nil {
		return nil, fmt.Errorf("intent: reading the fleet-control replay bound: %w", err)
	}
	if err := bound.Reserve(applied); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBoundUnwritable, err)
	}
	return &FleetControlSubscriber{Key: key, target: target, bound: bound, applied: applied}, nil
}

// Apply verifies and applies one signed control.
func (f *FleetControlSubscriber) Apply(raw []byte) error {
	err := f.apply(raw)
	if err != nil {
		f.Rejected.Add(1)
	}
	return err
}

func (f *FleetControlSubscriber) apply(raw []byte) error {
	var signed corev1.SignedUpdate
	if err := proto.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("intent: bad signed fleet control: %w", err)
	}
	if len(f.Key) == 0 {
		return errors.New("intent: no control-plane key configured; refusing an unverifiable fleet control")
	}
	if !ed25519.Verify(f.Key, signed.GetPayload(), signed.GetSignature()) {
		return errors.New("intent: fleet-control signature does not verify")
	}
	var c corev1.FleetControl
	if err := proto.Unmarshal(signed.GetPayload(), &c); err != nil {
		return fmt.Errorf("intent: bad fleet-control payload: %w", err)
	}
	// One rule, one home (core.AcceptsWireVersion): a version check spelled per package is a version
	// rule with a different answer per package.
	if !core.AcceptsWireVersion(c.GetVersion()) {
		return fmt.Errorf("%w: %d", ErrFleetVersion, c.GetVersion())
	}
	if v := c.GetVerb(); v == corev1.FleetVerb_FLEET_VERB_UNSPECIFIED {
		return errors.New("intent: fleet control carries no verb")
	}
	// EXPIRY, evaluated on arrival AND meaningful: a control with no bound, or a lapsed one, is refused.
	// A disable that cannot lapse is a product that is off and nobody remembers turning off.
	exp := c.GetExpiresAt()
	if exp == nil || !exp.AsTime().After(time.Now()) {
		return errors.New("intent: fleet control is expired or carries no expiry")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	// REPLAY: refuse anything at or below the highest sequence already applied. Without this, an attacker
	// who captured a legitimate DISABLE could re-send it after an operator restored enforcement, and it
	// would verify perfectly every time.
	if c.GetSequence() <= f.applied {
		return fmt.Errorf("intent: fleet control sequence %d is not above the applied %d (replay)",
			c.GetSequence(), f.applied)
	}
	// PERSIST BEFORE APPLYING, and refuse the control if the bound cannot be written (SEC-B).
	//
	// The order is the property. Applying first and persisting after leaves a window in which the
	// control has taken effect and nothing records that it did, so a crash inside that window restores a
	// bound BELOW a control that already ran — which is the replay this refuses, reintroduced by the
	// code meant to prevent it.
	//
	// Persisting first can instead lose a control to a crash. That asymmetry is deliberate and matches
	// this channel's stated bias: a lost DISABLE leaves the host ENFORCING and the control plane free to
	// re-issue at a higher sequence, while a replayed DISABLE turns the product off. Everything here
	// fails toward enforcing.
	if f.bound != nil {
		if err := f.bound.Reserve(c.GetSequence()); err != nil {
			return fmt.Errorf("intent: refusing fleet control sequence %d — its replay bound could not "+
				"be persisted (%w); applying it would leave a restart replaying it", c.GetSequence(), err)
		}
	}
	f.applied = c.GetSequence()

	source := "fleet:" + c.GetControlId()
	switch c.GetVerb() {
	case corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE:
		reason := c.GetReason()
		if reason == "" {
			reason = "fleet-wide enforcement disable"
		}
		f.target.Engage(reason, source)
	case corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_RESTORE:
		f.target.Disengage(source)
	}
	f.Applied.Add(1)
	return nil
}

// AppliedSequence is the highest sequence this consumer has applied — the answer to "has this host caught
// up", and the value an operator compares across a fleet mid-disable.
func (f *FleetControlSubscriber) AppliedSequence() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied
}

// ErrBoundUnwritable means the replay-bound file could be read but not written. It is separated from
// every other failure because it is the one a caller may legitimately downgrade: a read-only or ephemeral
// root filesystem is a real deployment shape, and on a path the operator never chose, refusing to start
// is worse than an in-memory bound that is loudly announced. Nothing else here is downgradable — a
// corrupt bound in particular is a reason to stop, since "start fresh at 0" is the attacker's preferred
// outcome.
var ErrBoundUnwritable = errors.New("intent: the fleet-control replay bound is not writable")

// OpenReplayBound opens the durable fleet-control replay bound at path (SEC-B).
//
// telemetrySeqPath is whatever OPENSHIELD_SEQ_FILE is set to, and the only reason it is a parameter is
// to REFUSE sharing. The two files hold numbers with the same type and opposite meanings: the telemetry
// sequence is a publisher high-water that advances once per hundred messages, while this is a consumer
// bound that advances once per fleet control ever issued. Pointed at one file, the telemetry high-water
// would become the replay bound within seconds of boot, and every legitimate control below it would be
// refused as a replay — a host that can no longer be told to stop enforcing, failing in the direction
// that looks like nothing is wrong. It is a plausible mistake to make once, and the resulting behaviour
// is nearly undiagnosable, so it is a startup error.
func OpenReplayBound(path, telemetrySeqPath string) (natsx.SeqStore, error) {
	if path == "" {
		return nil, errors.New("intent: no path for the fleet-control replay bound")
	}
	if telemetrySeqPath != "" {
		a, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("intent: replay bound path: %w", err)
		}
		b, err := filepath.Abs(telemetrySeqPath)
		if err != nil {
			return nil, fmt.Errorf("intent: telemetry sequence path: %w", err)
		}
		if a == b {
			return nil, fmt.Errorf("intent: the fleet-control replay bound and the telemetry sequence "+
				"are both %s; they are different numbers and sharing a file makes this host refuse "+
				"every fleet control as a replay", a)
		}
	}
	// Prove it READS and WRITES here, at configuration time, so a caller can tell a path problem it may
	// downgrade from one it must not. Doing this only inside the subscriber would collapse both into one
	// error at a point where the caller no longer knows whether the operator chose the path.
	store := natsx.NewFileSeqStore(path)
	applied, err := store.Load()
	if err != nil {
		return nil, err
	}
	if err := store.Reserve(applied); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrBoundUnwritable, path, err)
	}
	return store, nil
}

// Subscribe wires the subscriber; a rejected control is counted so a forgery flood is observable.
func (f *FleetControlSubscriber) Subscribe(conn *nats.Conn) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectFleetControl, func(m *nats.Msg) {
		_ = f.Apply(m.Data) // Apply counts its own rejections
	})
}
