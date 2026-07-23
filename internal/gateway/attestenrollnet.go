package gateway

import (
	"crypto/subtle"
	"crypto/x509"
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
	token          string // the pre-auth token this enrollment was authorized by (R34-2); consumed on success
}

// EnrollmentResponder is the gateway side of automated network enrollment (ZT-1):
// it issues a credential-activation challenge (step 1) and, only after the device
// returns the secret recovered by activating it with its TPM (step 2), enrolls the
// device into the verifier — the AK proven genuine-TPM-resident by the activation.
type EnrollmentResponder struct {
	verifier *AttestationVerifier
	mu       sync.Mutex
	pending  map[string]pendingEnroll
	// tokens is the set of operator-provisioned pre-auth tokens still unused (R34-2). When
	// requireToken is set, an enroll request MUST present a token in this set; the token is
	// consumed on a SUCCESSFUL enrollment (single-use), so a leaked challenge cannot be replayed
	// to enroll a second device. Empty + requireToken=false preserves the legacy (unauthenticated)
	// behavior for a deployment that has not turned pre-auth on.
	tokens       map[string]struct{}
	requireToken bool
	// ekRoots is the manufacturer-root pool an EK certificate must chain to (R34-2 part 2). When
	// requireEKCert is set, an enroll request MUST carry an ek_cert that chains to this pool AND
	// whose public key equals the submitted ek_public — anchoring the EK to a genuine vendor-
	// certified TPM. Credential activation proves EK/AK co-residence; this proves the EK is real.
	ekRoots       *x509.CertPool
	requireEKCert bool
}

// NewEnrollmentResponder wires a responder to a verifier.
func NewEnrollmentResponder(v *AttestationVerifier) *EnrollmentResponder {
	return &EnrollmentResponder{verifier: v, pending: map[string]pendingEnroll{}, tokens: map[string]struct{}{}}
}

// RequireEnrollTokens turns on pre-authorization (R34-2): only a device presenting one of these
// operator-provisioned tokens may enroll, and each token authorizes exactly ONE enrollment. Calling
// it with no tokens turns enforcement on with an empty set — every enrollment is then refused, which
// is the safe failure (a misconfigured operator denies rather than admits).
func (e *EnrollmentResponder) RequireEnrollTokens(toks ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requireToken = true
	for _, t := range toks {
		if t != "" {
			e.tokens[t] = struct{}{}
		}
	}
}

// RequireEKCertChain turns on EK-certificate anchoring (R34-2 part 2): only a device whose EK
// certificate chains to roots and whose EK public key matches the certificate may enroll. Passing a nil
// pool turns enforcement ON with no roots, so EVERY enrollment is refused — the safe failure for a
// misconfigured operator (deny rather than admit an uncertified EK), mirroring RequireEnrollTokens.
func (e *EnrollmentResponder) RequireEKCertChain(roots *x509.CertPool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requireEKCert = true
	e.ekRoots = roots
}

// tokenValid reports whether tok is a currently-unused pre-auth token, comparing in constant time so
// a timing side-channel does not reveal a valid token prefix. Caller holds e.mu.
func (e *EnrollmentResponder) tokenValid(tok string) bool {
	if tok == "" {
		return false
	}
	ok := false
	for known := range e.tokens {
		if subtle.ConstantTimeCompare([]byte(known), []byte(tok)) == 1 {
			ok = true
		}
	}
	return ok
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
	// R34-2: pre-authorization. Credential activation (below) proves the AK is genuine-TPM-resident,
	// but NOT that this device is authorized to enroll under this subject — without a token check any
	// device with a co-resident TPM (incl. swtpm) self-enrolls under any pseudonym. Reject an
	// unrecognized token BEFORE issuing a challenge or storing any pending state.
	e.mu.Lock()
	if e.requireToken && !e.tokenValid(req.GetEnrollToken()) {
		e.mu.Unlock()
		return nil, fmt.Errorf("enrollment not pre-authorized")
	}
	requireEK, ekRoots := e.requireEKCert, e.ekRoots
	e.mu.Unlock()
	// R34-2 part 2: EK-certificate anchor. Credential activation (below) proves the AK is co-resident
	// with the submitted EK, but NOT that the EK is a genuine vendor-certified TPM — a fabricated (e.g.
	// swtpm) EK passes activation. Refuse an EK whose certificate does not chain to a manufacturer root
	// (and is not bound to the submitted EK public key) BEFORE issuing a challenge or storing pending
	// state, so an uncertified device learns nothing beyond the refusal.
	if requireEK {
		if err := attest.VerifyEKCert(req.GetEkCert(), ekRoots, req.GetEkPublic()); err != nil {
			return nil, fmt.Errorf("EK not manufacturer-attested: %w", err)
		}
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
	e.pending[req.GetSubject()] = pendingEnroll{akPublic: req.GetAkPublic(), golden: golden, expectedSecret: secret, token: req.GetEnrollToken()}
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
	// R34-2: consume the pre-auth token on SUCCESS — single-use, so a captured token cannot enroll a
	// second device. A failed activation above leaves the token spendable (a legitimate retry).
	if e.requireToken && p.token != "" {
		delete(e.tokens, p.token)
	}
	e.mu.Unlock()
	return &corev1.AttestationEnrollResult{Enrolled: true}
}
