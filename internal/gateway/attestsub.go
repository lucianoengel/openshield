package gateway

import (
	"sync/atomic"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// AttestationResponder is the gateway side of the ZT-1 attestation transport: it
// answers a device's challenge request with a fresh nonce from the verifier, and
// verifies each published report into the verifier. It carries no extra
// authentication layer — an attestation report IS a TPM-signed quote, verified by
// VerifyReport against the enrolled AK, so a forged report simply fails.
type AttestationResponder struct {
	verifier *AttestationVerifier
	// Rejected counts reports dropped for failing verification (unenrolled, stale
	// nonce, bad quote, or PCR drift) — observable, never a silent no-op.
	Rejected atomic.Int64
}

// NewAttestationResponder wires a responder to a verifier.
func NewAttestationResponder(v *AttestationVerifier) *AttestationResponder {
	return &AttestationResponder{verifier: v}
}

// ServeChallenge answers challenge requests: the request payload is the device's
// subject; the reply is a fresh nonce for it. An unenrolled subject (or any
// verifier error) replies with an empty payload, so the device cannot proceed.
func (a *AttestationResponder) ServeChallenge(conn *nats.Conn) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectAttestChallenge, func(m *nats.Msg) {
		nonce, err := a.verifier.Challenge(string(m.Data))
		if err != nil {
			_ = m.Respond(nil)
			return
		}
		_ = m.Respond(nonce)
	})
}

// SubscribeReports verifies each published report into the verifier; a report that
// fails verification is dropped and counted (Rejected), so a forged-report flood is
// observable, not silent.
func (a *AttestationResponder) SubscribeReports(conn *nats.Conn) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectAttestReport, func(m *nats.Msg) {
		var report corev1.AttestationReport
		if err := proto.Unmarshal(m.Data, &report); err != nil {
			a.Rejected.Add(1)
			return
		}
		if err := a.verifier.VerifyReport(&report); err != nil {
			a.Rejected.Add(1)
		}
	})
}
