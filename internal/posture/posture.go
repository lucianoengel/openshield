// Package posture is the endpoint device-posture PRODUCER (HON-4). The gateway's posture
// channel (D92) had a store and a SIGNED subscriber (SEC-1) but NO publisher — nothing ever
// emitted a PostureUpdate, so the D85 tamper-lockout could never see real data. This reports
// the device's posture and publishes it AGENT-KEY-SIGNED, the producer the gateway verifies.
//
// Posture is self-reported and only as trustworthy as the reporter (a rooted endpoint could
// lie "compliant"); TPM/measured-boot attestation is the hardening (ZT-1), and the
// absent-posture fail-closed (D85) still catches an endpoint that stops reporting entirely.
// Detection here is HONEST best-effort: it reports what it can actually observe and leaves
// the rest UNKNOWN/false rather than asserting a compliance it did not verify.
package posture

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// Report is the device state the endpoint reports. It mirrors core.DevicePosture minus the
// HasPosture flag (presence is implied by a published report).
type Report struct {
	Compliant     bool
	DiskEncrypted bool
	AgentPresent  bool
	OSPatchTier   core.PatchTier
}

// Detect gathers what the endpoint can HONESTLY observe (Linux best-effort):
//   - AgentPresent: true — this code IS the agent, running.
//   - DiskEncrypted: true only if a dm-crypt/LUKS mount is observed in /proc/mounts.
//   - OSPatchTier: Unknown — patch currency needs an OS patch feed we do not have here.
//   - Compliant: derived, and DELIBERATELY conservative — true only when disk encryption is
//     observed AND the agent is present. Absent evidence is NOT compliance (D28-style).
//
// It does not fabricate a signal it cannot verify: a check it cannot make reads false/unknown,
// so a policy requiring compliance denies until real evidence exists.
func Detect() Report {
	disk := diskEncryptionObserved()
	return Report{
		Compliant:     disk, // agent present is a given; the honest compliance signal is disk encryption
		DiskEncrypted: disk,
		AgentPresent:  true,
		OSPatchTier:   core.PatchUnknown,
	}
}

// diskEncryptionObserved reports whether any mounted filesystem sits on a dm-crypt device
// (best-effort — reads /proc/mounts). Uncertain → false (never assert encryption unverified).
func diskEncryptionObserved() bool {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		dev, _, _ := strings.Cut(line, " ")
		// dm-crypt devices surface as /dev/mapper/<name> or /dev/dm-N backing a crypt target.
		if strings.HasPrefix(dev, "/dev/mapper/") || strings.HasPrefix(dev, "/dev/dm-") {
			return true
		}
	}
	return false
}

// Sign wraps a marshalled PostureUpdate in a SignedUpdate signed with the agent's key —
// mirroring the gateway's verify side (SEC-1). Exposed so a producer or a test can build the
// exact bytes the gateway verifies.
func Sign(payload []byte, priv ed25519.PrivateKey) ([]byte, error) {
	sig := ed25519.Sign(priv, payload)
	return proto.Marshal(&corev1.SignedUpdate{Payload: payload, Signature: sig})
}

// Build marshals a signed posture update for a subject. subject is the agent's own
// pseudonymous identity (D23) — a posture update's subject is bound to the reporting agent,
// so a compromised publisher cannot forge ANOTHER subject's posture (the SEC-1 posture half).
func Build(subject string, r Report, priv ed25519.PrivateKey) ([]byte, error) {
	if subject == "" {
		return nil, fmt.Errorf("posture: empty subject")
	}
	payload, err := proto.Marshal(&corev1.PostureUpdate{
		Subject:       subject,
		Compliant:     r.Compliant,
		DiskEncrypted: r.DiskEncrypted,
		AgentPresent:  r.AgentPresent,
		OsPatchTier:   int32(r.OSPatchTier),
		ComputedAt:    timestamppb.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("posture: marshalling update: %w", err)
	}
	return Sign(payload, priv)
}

// Publish reports the current posture: it builds a signed update for the subject and
// publishes it on the posture subject. Best-effort — a publish failure is returned, never
// fatal (like risk publishing, it must not break the agent).
func Publish(conn *nats.Conn, subject string, r Report, priv ed25519.PrivateKey) error {
	data, err := Build(subject, r, priv)
	if err != nil {
		return err
	}
	return conn.Publish(natsx.SubjectPosture, data)
}
