package gateway_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/attest"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/posture"
)

// TestEnrollmentDistributionRoundTrip proves a distributed enrollment is
// functionally identical to a programmatic one: capture a swtpm device's record,
// write it to a file, load it into a fresh verifier, and the device attests end to
// end over the live channel.
func TestEnrollmentDistributionRoundTrip(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")
	extendPCR(t, d.tpm, 23, "kernel")

	const subject = "sub_device1"
	record, err := posture.BuildEnrollment(d.tpm, d.ak, subject, pcrs)
	if err != nil {
		t.Fatalf("build enrollment: %v", err)
	}
	data, err := attest.MarshalEnrollments([]attest.AttestationEnrollment{record})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "enrollments.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// A gateway that only ever saw the distributed file — no programmatic Enroll.
	v := gateway.NewAttestationVerifier()
	n, err := gateway.LoadAttestationEnrollments(v, path)
	if err != nil {
		t.Fatalf("load enrollments: %v", err)
	}
	if n != 1 {
		t.Fatalf("loaded %d enrollments, want 1", n)
	}

	url := embeddedNATSURL(t)
	gwConn, _ := nats.Connect(url)
	t.Cleanup(gwConn.Close)
	epConn, _ := nats.Connect(url)
	t.Cleanup(epConn.Close)

	responder := gateway.NewAttestationResponder(v)
	if _, err := responder.ServeChallenge(gwConn); err != nil {
		t.Fatal(err)
	}
	if _, err := responder.SubscribeReports(gwConn); err != nil {
		t.Fatal(err)
	}

	if err := posture.Attest(epConn, d.tpm, d.ak, subject, pcrs); err != nil {
		t.Fatalf("attest: %v", err)
	}
	attestWaitFor(t, func() bool { return v.IsAttested(subject) })
}

// TestEnrollmentLoadIsAtomic proves a load with one good and one bad record fails
// WITHOUT partially enrolling the good one — the operator gets an error, not a
// silently-partial verifier. This isolates the validate-all-before-enroll-any
// property: the good record uses a real (parseable) AK, so only the atomic
// pre-validation prevents it from being enrolled when the bad record is present.
func TestEnrollmentLoadIsAtomic(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")

	good, err := posture.BuildEnrollment(d.tpm, d.ak, "sub_aaa_good", pcrs)
	if err != nil {
		t.Fatalf("build enrollment: %v", err)
	}
	// A second record with the same real (parseable) AK but an empty baseline —
	// invalid, yet its AK parses, so only Validate/atomicity catches it.
	bad := attest.AttestationEnrollment{Subject: "sub_zzz_bad", AKPublic: good.AKPublic, Golden: map[int][]byte{}}

	data, err := attest.MarshalEnrollments([]attest.AttestationEnrollment{good, bad})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "mixed.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	v := gateway.NewAttestationVerifier()
	if _, err := gateway.LoadAttestationEnrollments(v, path); err == nil {
		t.Fatal("a mixed good+bad enrollment file should fail the load")
	}
	// The good record must NOT have been enrolled (no partial state): a challenge
	// for it is refused.
	if _, err := v.Challenge("sub_aaa_good"); err == nil {
		t.Fatal("the good record was partially enrolled despite the load error")
	}
}

// TestEnrollmentLoadFailsClosed proves a malformed record fails the whole load
// (never a silent skip that would leave the operator believing a device is
// enrolled while it is silently denied).
func TestEnrollmentLoadFailsClosed(t *testing.T) {
	cases := map[string]string{
		"empty subject":  `{"enrollments":[{"subject":"","ak_public":"AQ==","pcrs":{"0":"00"}}]}`,
		"bad AK base64":  `{"enrollments":[{"subject":"s","ak_public":"!!notb64","pcrs":{"0":"00"}}]}`,
		"unparseable AK": `{"enrollments":[{"subject":"s","ak_public":"//8=","pcrs":{"0":"00"}}]}`,
		"empty baseline": `{"enrollments":[{"subject":"s","ak_public":"AQ==","pcrs":{}}]}`,
		"empty file":     `{"enrollments":[]}`,
		"bad hex PCR":    `{"enrollments":[{"subject":"s","ak_public":"AQ==","pcrs":{"0":"zz"}}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "e.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			v := gateway.NewAttestationVerifier()
			if _, err := gateway.LoadAttestationEnrollments(v, path); err == nil {
				t.Fatalf("%s: expected an error, got nil", name)
			}
		})
	}
}
