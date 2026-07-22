package gateway

import (
	"fmt"
	"sync"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/attest"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// pendingEnroll is the server-side state between the two enrollment steps: the
// device's AK and baseline, and the secret it must recover to prove its AK
// genuine-TPM-resident.
type pendingEnroll struct {
	akPublic       []byte
	golden         map[int][]byte
	expectedSecret []byte
}

// EnrollmentResponder is the gateway side of automated network enrollment (ZT-1):
// it issues a credential-activation challenge (step 1) and, only after the device
// returns the secret recovered by activating it with its TPM (step 2), enrolls the
// device into the verifier — the AK proven genuine-TPM-resident by the activation.
type EnrollmentResponder struct {
	verifier *AttestationVerifier
	mu       sync.Mutex
	pending  map[string]pendingEnroll
}

// NewEnrollmentResponder wires a responder to a verifier.
func NewEnrollmentResponder(v *AttestationVerifier) *EnrollmentResponder {
	return &EnrollmentResponder{verifier: v, pending: map[string]pendingEnroll{}}
}

// ServeEnroll answers step 1: build a credential-activation challenge for the
// submitted EK/AK and stash the pending enrollment. Any failure replies an error
// and stores no pending state (no enrollment can then complete).
func (e *EnrollmentResponder) ServeEnroll(conn *nats.Conn) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectAttestEnroll, func(m *nats.Msg) {
		challenge, err := e.handleEnroll(m.Data)
		if err != nil {
			challenge = &corev1.AttestationEnrollChallenge{Error: err.Error()}
		}
		data, _ := proto.Marshal(challenge)
		_ = m.Respond(data)
	})
}

func (e *EnrollmentResponder) handleEnroll(data []byte) (*corev1.AttestationEnrollChallenge, error) {
	var req corev1.AttestationEnrollRequest
	if err := proto.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("bad enroll request")
	}
	if req.GetSubject() == "" {
		return nil, fmt.Errorf("enroll request has no subject")
	}
	challenge, secret, err := attest.NewChallenge(req.GetEkPublic(), req.GetAkName())
	if err != nil {
		return nil, fmt.Errorf("building challenge: %w", err)
	}
	golden := make(map[int][]byte, len(req.GetGolden()))
	for k, v := range req.GetGolden() {
		golden[int(k)] = v
	}
	e.mu.Lock()
	e.pending[req.GetSubject()] = pendingEnroll{akPublic: req.GetAkPublic(), golden: golden, expectedSecret: secret}
	e.mu.Unlock()
	return &corev1.AttestationEnrollChallenge{
		CredentialBlob:  challenge.CredentialBlob,
		EncryptedSecret: challenge.EncryptedSecret,
	}, nil
}

// ServeActivate answers step 2: verify the recovered secret against the pending
// enrollment and, only on a match, enroll the device (the AK is thereby proven
// genuine-TPM-resident). Any failure replies enrolled=false and enrolls nothing.
func (e *EnrollmentResponder) ServeActivate(conn *nats.Conn) (*nats.Subscription, error) {
	return conn.Subscribe(natsx.SubjectAttestActivate, func(m *nats.Msg) {
		result := e.handleActivate(m.Data)
		data, _ := proto.Marshal(result)
		_ = m.Respond(data)
	})
}

func (e *EnrollmentResponder) handleActivate(data []byte) *corev1.AttestationEnrollResult {
	var act corev1.AttestationActivation
	if err := proto.Unmarshal(data, &act); err != nil {
		return &corev1.AttestationEnrollResult{Error: "bad activation"}
	}
	e.mu.Lock()
	p, ok := e.pending[act.GetSubject()]
	e.mu.Unlock()
	if !ok {
		return &corev1.AttestationEnrollResult{Error: "no pending enrollment"}
	}
	if !attest.VerifyActivation(p.expectedSecret, act.GetSecret()) {
		return &corev1.AttestationEnrollResult{Error: "activation did not verify"}
	}
	akPub, err := attest.ParseAKPublicKey(p.akPublic)
	if err != nil {
		return &corev1.AttestationEnrollResult{Error: "unparseable AK"}
	}
	if err := e.verifier.Enroll(act.GetSubject(), akPub, p.golden); err != nil {
		return &corev1.AttestationEnrollResult{Error: err.Error()}
	}
	e.mu.Lock()
	delete(e.pending, act.GetSubject())
	e.mu.Unlock()
	return &corev1.AttestationEnrollResult{Enrolled: true}
}
