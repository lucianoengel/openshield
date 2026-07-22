package gateway_test

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/posture"
)

// loopHarness enrolls a swtpm device, starts the gateway responder over embedded
// NATS, and returns the verifier, responder, and an endpoint connection.
func loopHarness(t *testing.T, d *device, subject string, pcrs []int) (*gateway.AttestationVerifier, *gateway.AttestationResponder, *nats.Conn) {
	t.Helper()
	v := gateway.NewAttestationVerifier()
	if err := v.Enroll(subject, d.ak.PublicKey(), d.golden(t, pcrs)); err != nil {
		t.Fatalf("enroll: %v", err)
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
	return v, responder, epConn
}

// TestReattestLoopKeepsAttested proves the loop keeps a good device attested across
// successive cycles.
func TestReattestLoopKeepsAttested(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")
	extendPCR(t, d.tpm, 23, "kernel")
	const subject = "sub_device1"
	v, _, epConn := loopHarness(t, d, subject, pcrs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go posture.AttestLoop(ctx, epConn, d.tpm, d.ak, subject, pcrs, 30*time.Millisecond, nil)

	attestWaitFor(t, func() bool { return v.IsAttested(subject) })
	// Still attested after several more cycles.
	time.Sleep(120 * time.Millisecond)
	if !v.IsAttested(subject) {
		t.Fatal("device lost attestation while in its golden state")
	}
}

// TestReattestLoopDetectsDrift proves continuous verification: after the device
// drifts, the loop's next re-attestation is rejected and the device loses its
// attested status — the loop re-checks, it does not attest once.
func TestReattestLoopDetectsDrift(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")
	extendPCR(t, d.tpm, 23, "kernel-v1")
	const subject = "sub_device1"
	v, responder, epConn := loopHarness(t, d, subject, pcrs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go posture.AttestLoop(ctx, epConn, d.tpm, d.ak, subject, pcrs, 30*time.Millisecond, nil)

	attestWaitFor(t, func() bool { return v.IsAttested(subject) })

	// The device drifts after enrollment; the next re-attestation must be rejected.
	extendPCR(t, d.tpm, 23, "kernel-v2-unexpected")
	attestWaitFor(t, func() bool { return responder.Rejected.Load() >= 1 })
	// And it is no longer attested (steady state after a couple more cycles).
	time.Sleep(90 * time.Millisecond)
	if v.IsAttested(subject) {
		t.Fatal("a drifted device stayed attested — continuous verification failed")
	}
}

// TestReattestLoopCancels proves the loop returns promptly on context cancellation.
func TestReattestLoopCancels(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16}
	extendPCR(t, d.tpm, 16, "bootloader")
	const subject = "sub_device1"
	_, _, epConn := loopHarness(t, d, subject, pcrs)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		posture.AttestLoop(ctx, epConn, d.tpm, d.ak, subject, pcrs, 20*time.Millisecond, nil)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("AttestLoop did not return on cancellation")
	}
}
