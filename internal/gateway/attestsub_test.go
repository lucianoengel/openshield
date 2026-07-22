package gateway_test

import (
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/gateway"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"github.com/lucianoengel/openshield/internal/posture"
)

func embeddedNATSURL(t *testing.T) string {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded NATS did not become ready")
	}
	t.Cleanup(srv.Shutdown)
	return srv.ClientURL()
}

func attestWaitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

// TestAttestationTransportEndToEnd drives the full ZT-1 attestation transport over
// an embedded NATS server and a real swtpm: the device requests a challenge, quotes
// over the returned nonce, publishes the report, and the gateway responder verifies
// it — flipping the device to attested on the live channel.
func TestAttestationTransportEndToEnd(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")
	extendPCR(t, d.tpm, 23, "kernel")

	const subject = "sub_device1"
	v := gateway.NewAttestationVerifier()
	if err := v.Enroll(subject, d.ak.PublicKey(), d.golden(t, pcrs)); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	url := embeddedNATSURL(t)
	gwConn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gwConn.Close)
	epConn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(epConn.Close)

	responder := gateway.NewAttestationResponder(v)
	if _, err := responder.ServeChallenge(gwConn); err != nil {
		t.Fatal(err)
	}
	if _, err := responder.SubscribeReports(gwConn); err != nil {
		t.Fatal(err)
	}

	// The device attests over the live channel.
	if err := posture.Attest(epConn, d.tpm, d.ak, subject, pcrs); err != nil {
		t.Fatalf("attest: %v", err)
	}
	attestWaitFor(t, func() bool { return v.IsAttested(subject) })
}

// TestAttestationTransportForgedReportRejected proves a report with a mismatched
// nonce published on the channel is rejected and counted, not accepted.
func TestAttestationTransportForgedReportRejected(t *testing.T) {
	d := newDevice(t)
	pcrs := []int{16, 23}
	extendPCR(t, d.tpm, 16, "bootloader")

	const subject = "sub_device1"
	v := gateway.NewAttestationVerifier()
	_ = v.Enroll(subject, d.ak.PublicKey(), d.golden(t, pcrs))

	url := embeddedNATSURL(t)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)

	responder := gateway.NewAttestationResponder(v)
	if _, err := responder.SubscribeReports(conn); err != nil {
		t.Fatal(err)
	}
	// Issue a real challenge, but quote over a DIFFERENT (attacker-chosen) nonce.
	if _, err := v.Challenge(subject); err != nil {
		t.Fatal(err)
	}
	report := d.report(t, subject, []byte("this-is-not-the-issued-nonce-000"), pcrs)
	data, _ := proto.Marshal(report)
	if err := conn.Publish(natsx.SubjectAttestReport, data); err != nil {
		t.Fatal(err)
	}

	attestWaitFor(t, func() bool { return responder.Rejected.Load() == 1 })
	if v.IsAttested(subject) {
		t.Fatal("a forged report must not mark the device attested")
	}
}

// TestAttestationChallengeUnenrolled proves the challenge reply is empty for an
// unenrolled subject, so the device cannot proceed.
func TestAttestationChallengeUnenrolled(t *testing.T) {
	v := gateway.NewAttestationVerifier()
	url := embeddedNATSURL(t)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)

	responder := gateway.NewAttestationResponder(v)
	if _, err := responder.ServeChallenge(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := conn.Request(natsx.SubjectAttestChallenge, []byte("sub_unknown"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(resp.Data) != 0 {
		t.Fatalf("unenrolled challenge returned a nonce (%d bytes), want empty", len(resp.Data))
	}
}
