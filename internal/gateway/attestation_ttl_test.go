package gateway_test

import (
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway"
)

// TestAttestationVerdictExpires (R34-1): a device that attests once and then STOPS
// loses its attested verdict after the TTL — a compromised-but-silent endpoint must
// not stay Attested=true forever. Drives the TTL with an injected clock.
func TestAttestationVerdictExpires(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")
	extendPCR(t, d.tpm, 23, "kernel")
	const subject = "sub_ttl"

	v := gateway.NewAttestationVerifier()
	v.SetTTL(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	clock := base
	gateway.SetVerifierClock(v, func() time.Time { return clock })

	if err := v.Enroll(subject, d.ak.PublicKey(), d.golden(t, pcrs)); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	nonce, _ := v.Challenge(subject)
	if err := v.VerifyReport(d.report(t, subject, nonce, pcrs)); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Fresh → attested.
	if !v.IsAttested(subject) {
		t.Fatal("device should be attested immediately after a valid report")
	}
	// Still within the TTL → attested.
	clock = base.Add(30 * time.Second)
	if !v.IsAttested(subject) {
		t.Fatal("device should still be attested within the TTL")
	}
	// Past the TTL with no fresh report → NOT attested (the device stopped attesting).
	clock = base.Add(90 * time.Second)
	if v.IsAttested(subject) {
		t.Fatal("a device that stopped attesting must lose its verdict after the TTL (R34-1)")
	}
}
