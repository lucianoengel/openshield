package gateway_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/attest"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/posture"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// testCA is a synthetic TPM-vendor root for the enroll-path EK-cert tests.
type testCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vendor root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCA{cert: cert, key: key, roots: pool}
}

func (ca testCA) ekCert(t *testing.T, ekPub *ecdsa.PublicKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "EK"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, ekPub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// ekCertHarness starts the enrollment responder with EK-certificate anchoring ON for roots.
func ekCertHarness(t *testing.T, roots *x509.CertPool) (*gateway.AttestationVerifier, *nats.Conn) {
	t.Helper()
	v := gateway.NewAttestationVerifier()
	url := embeddedNATSURL(t)
	gwConn, _ := nats.Connect(url)
	t.Cleanup(gwConn.Close)
	epConn, _ := nats.Connect(url)
	t.Cleanup(epConn.Close)

	enroller := gateway.NewEnrollmentResponder(v)
	enroller.RequireEKCertChain(roots)
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

func requestEnroll(t *testing.T, epConn *nats.Conn, req *corev1.AttestationEnrollRequest) *corev1.AttestationEnrollChallenge {
	t.Helper()
	data, _ := proto.Marshal(req)
	resp, err := epConn.Request(natsx.SubjectAttestEnroll, data, posture.AttestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	var ch corev1.AttestationEnrollChallenge
	if err := proto.Unmarshal(resp.Data, &ch); err != nil {
		t.Fatal(err)
	}
	return &ch
}

// TestEnrollRefusesUncertifiedEK (R34-2, Test #5): the EK-cert anchor rejects an enrollment whose EK is
// not certified by a manufacturer root BEFORE any challenge, so a fabricated EK (incl. swtpm) cannot
// self-enroll even with a valid pre-auth token. Both an absent cert and a non-chaining cert are refused,
// and the device is never enrolled.
//
// The device presents a REAL, well-formed EK public key (so the request would otherwise pass
// NewChallenge) — only the missing/rogue EK certificate can refuse it. This isolates the EK-cert guard:
// dropping the VerifyEKCert call in handleEnroll lets the no-cert request be CHALLENGED (a real EK builds
// a valid challenge), so the "must be refused / never enrolled" assertions FAIL.
func TestEnrollRefusesUncertifiedEK(t *testing.T) {
	d := newDevice(t)
	ek, err := d.tpm.CreateEK()
	if err != nil {
		t.Fatalf("create EK: %v", err)
	}
	defer func() { _ = d.tpm.FlushEK(ek) }()
	extendPCR(t, d.tpm, 16, "bootloader")

	ca := newTestCA(t)
	v, epConn := ekCertHarness(t, ca.roots)

	// A real EK but NO EK certificate → refused at step 1, no challenge, never enrolled.
	base := func(subject string) *corev1.AttestationEnrollRequest {
		return &corev1.AttestationEnrollRequest{
			Subject: subject, EkPublic: ek.PublicKeyBytes(), AkPublic: d.ak.PublicKeyBytes(),
			AkName: d.ak.Name(), Golden: map[uint32][]byte{16: mustGolden(t, d, 16)},
		}
	}
	ch := requestEnroll(t, epConn, base("sub_nocert"))
	if ch.GetError() == "" {
		t.Fatal("an enroll with no EK certificate was accepted (challenge issued) — EK anchor not enforced")
	}
	if ch.GetCredentialBlob() != nil {
		t.Fatal("a refused enroll still returned a credential-activation challenge")
	}
	if _, cerr := v.Challenge("sub_nocert"); cerr == nil {
		t.Fatal("an uncertified device was enrolled")
	}

	// A genuine EK cert bound to this EK but signed by a DIFFERENT (untrusted) root → refused.
	rogue := newTestCA(t) // not in ca.roots
	ekPub, err := attest.ParseEKPublicKey(ek.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	req := base("sub_rogue")
	req.EkCert = rogue.ekCert(t, ekPub)
	if ch := requestEnroll(t, epConn, req); ch.GetError() == "" {
		t.Fatal("an EK cert that does not chain to a configured manufacturer root was accepted")
	}
}

// TestEnrollAcceptsManufacturerCertifiedEK (R34-2) — swtpm-gated: a device with a REAL EK whose
// certificate chains to a manufacturer root and is bound to its EK public key passes the anchor and is
// challenged, then enrolls after real credential activation. Proves the anchor does not block a
// legitimate, certified device.
func TestEnrollAcceptsManufacturerCertifiedEK(t *testing.T) {
	d := newDevice(t)
	ek, err := d.tpm.CreateEK()
	if err != nil {
		t.Fatalf("create EK: %v", err)
	}
	defer func() { _ = d.tpm.FlushEK(ek) }()
	extendPCR(t, d.tpm, 16, "bootloader")

	// Certify the device's REAL EK public key with our synthetic manufacturer CA.
	ca := newTestCA(t)
	ekPub, err := attest.ParseEKPublicKey(ek.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	certDER := ca.ekCert(t, ekPub)

	v, epConn := ekCertHarness(t, ca.roots)

	ch := requestEnroll(t, epConn, &corev1.AttestationEnrollRequest{
		Subject:  "sub_certified",
		EkPublic: ek.PublicKeyBytes(),
		AkPublic: d.ak.PublicKeyBytes(),
		AkName:   d.ak.Name(),
		Golden:   map[uint32][]byte{16: mustGolden(t, d, 16)},
		EkCert:   certDER,
	})
	if ch.GetError() != "" {
		t.Fatalf("a manufacturer-certified EK was refused enrollment: %s", ch.GetError())
	}
	res := enrollStep2(t, epConn, d, ek, "sub_certified", ch)
	if !res.GetEnrolled() {
		t.Fatalf("a certified, genuinely-activated device was not enrolled: %s", res.GetError())
	}
	if _, cerr := v.Challenge("sub_certified"); cerr != nil {
		t.Fatalf("the certified device was not enrolled into the verifier: %v", cerr)
	}
}
