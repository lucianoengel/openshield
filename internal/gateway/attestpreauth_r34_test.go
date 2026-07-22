package gateway_test

import (
	"testing"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/attest"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/posture"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// preAuthHarness starts the enrollment responder with pre-authorization turned ON for the given
// tokens, and returns the verifier + an endpoint connection.
func preAuthHarness(t *testing.T, tokens ...string) (*gateway.AttestationVerifier, *nats.Conn) {
	t.Helper()
	v := gateway.NewAttestationVerifier()
	url := embeddedNATSURL(t)
	gwConn, _ := nats.Connect(url)
	t.Cleanup(gwConn.Close)
	epConn, _ := nats.Connect(url)
	t.Cleanup(epConn.Close)

	enroller := gateway.NewEnrollmentResponder(v)
	enroller.RequireEnrollTokens(tokens...)
	if _, err := enroller.ServeEnroll(gwConn); err != nil {
		t.Fatal(err)
	}
	if _, err := enroller.ServeActivate(gwConn); err != nil {
		t.Fatal(err)
	}
	if err := gwConn.Flush(); err != nil {
		t.Fatal(err)
	}
	return v, epConn
}

// enrollStep1 drives step 1 of the handshake manually with an explicit pre-auth token, returning the
// challenge (so a test can inject / omit the token that posture.Enroll does not expose).
func enrollStep1(t *testing.T, epConn *nats.Conn, d *device, ek *attest.EK, subject, token string, pcr int) *corev1.AttestationEnrollChallenge {
	t.Helper()
	req, _ := proto.Marshal(&corev1.AttestationEnrollRequest{
		Subject: subject, EkPublic: ek.PublicKeyBytes(), AkPublic: d.ak.PublicKeyBytes(), AkName: d.ak.Name(),
		Golden: map[uint32][]byte{uint32(pcr): mustGolden(t, d, pcr)}, EnrollToken: token,
	})
	resp, err := epConn.Request(natsx.SubjectAttestEnroll, req, posture.AttestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	var ch corev1.AttestationEnrollChallenge
	if err := proto.Unmarshal(resp.Data, &ch); err != nil {
		t.Fatal(err)
	}
	return &ch
}

// enrollStep2 activates the challenge on the device's real TPM and returns the enroll result.
func enrollStep2(t *testing.T, epConn *nats.Conn, d *device, ek *attest.EK, subject string, ch *corev1.AttestationEnrollChallenge) *corev1.AttestationEnrollResult {
	t.Helper()
	secret, err := d.tpm.Activate(ek, d.ak, &attest.Challenge{CredentialBlob: ch.GetCredentialBlob(), EncryptedSecret: ch.GetEncryptedSecret()})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	act, _ := proto.Marshal(&corev1.AttestationActivation{Subject: subject, Secret: secret})
	resp, err := epConn.Request(natsx.SubjectAttestActivate, act, posture.AttestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	var result corev1.AttestationEnrollResult
	if err := proto.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}
	return &result
}

// TestEnrollRequiresPreAuthToken (R34-2): with pre-authorization on, a genuine device (real EK/AK,
// real credential activation would succeed) is STILL refused enrollment unless it presents a valid
// operator-provisioned token — closing "any device with a co-resident TPM self-enrolls under any
// pseudonym". No challenge is even issued for a bad/absent token.
//
// Mutation: dropping the `requireToken && !tokenValid` guard in handleEnroll lets the no-token
// request enroll — the "must not be challenged/enrolled" assertions FAIL.
func TestEnrollRequiresPreAuthToken(t *testing.T) {
	d := newDevice(t)
	ek, err := d.tpm.CreateEK()
	if err != nil {
		t.Fatalf("create EK: %v", err)
	}
	defer func() { _ = d.tpm.FlushEK(ek) }()
	extendPCR(t, d.tpm, 16, "bootloader")

	v, epConn := preAuthHarness(t, "secret-enroll-token")

	// No token → refused at step 1 (an error challenge, no pending state, never enrolled).
	ch := enrollStep1(t, epConn, d, ek, "sub_untoken", "", 16)
	if ch.GetError() == "" {
		t.Fatal("an enroll with no pre-auth token was accepted (challenge issued) — pre-auth not enforced")
	}
	if _, cerr := v.Challenge("sub_untoken"); cerr == nil {
		t.Fatal("an unauthorized device was enrolled")
	}

	// Wrong token → also refused.
	chBad := enrollStep1(t, epConn, d, ek, "sub_badtoken", "not-the-token", 16)
	if chBad.GetError() == "" {
		t.Fatal("an enroll with a wrong pre-auth token was accepted")
	}

	// Correct token → challenge issued and, after real activation, enrolled.
	chOK := enrollStep1(t, epConn, d, ek, "sub_authed", "secret-enroll-token", 16)
	if chOK.GetError() != "" {
		t.Fatalf("a correctly pre-authorized enroll was refused: %s", chOK.GetError())
	}
	res := enrollStep2(t, epConn, d, ek, "sub_authed", chOK)
	if !res.GetEnrolled() {
		t.Fatalf("a correctly pre-authorized, genuinely-activated device was not enrolled: %s", res.GetError())
	}
}

// TestPreAuthTokenIsSingleUse (R34-2): a token authorizes exactly ONE enrollment; a captured token
// cannot be replayed to enroll a second device.
//
// Mutation: removing the `delete(e.tokens, p.token)` consume in handleActivate lets the second
// enrollment succeed — the "second use refused" assertion FAILS.
func TestPreAuthTokenIsSingleUse(t *testing.T) {
	d := newDevice(t)
	ek, err := d.tpm.CreateEK()
	if err != nil {
		t.Fatalf("create EK: %v", err)
	}
	defer func() { _ = d.tpm.FlushEK(ek) }()
	extendPCR(t, d.tpm, 16, "bootloader")

	_, epConn := preAuthHarness(t, "one-shot")

	// First enrollment spends the token.
	ch1 := enrollStep1(t, epConn, d, ek, "sub_first", "one-shot", 16)
	if ch1.GetError() != "" {
		t.Fatalf("first enroll refused: %s", ch1.GetError())
	}
	if res := enrollStep2(t, epConn, d, ek, "sub_first", ch1); !res.GetEnrolled() {
		t.Fatalf("first enroll did not complete: %s", res.GetError())
	}

	// Re-using the same token for a different subject must now be refused.
	ch2 := enrollStep1(t, epConn, d, ek, "sub_second", "one-shot", 16)
	if ch2.GetError() == "" {
		t.Fatal("a spent single-use token enrolled a second device — token reuse not prevented")
	}
}
