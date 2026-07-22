package posture

import (
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/attest"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// AttestTimeout bounds the challenge request round-trip.
const AttestTimeout = 5 * time.Second

// Attest performs one ZT-1 attestation round-trip from the endpoint: request a
// fresh nonce for subject, produce a TPM quote over it, and publish the report for
// the gateway to verify. subject MUST be the device's canonical pseudonym
// (pseudonym.Of, ADR-6) — the same key the gateway enrolled the device's AK under.
//
// The report is not separately signed: it is a TPM-signed quote that authenticates
// itself against the enrolled AK, so publishing it verbatim is safe.
func Attest(conn *nats.Conn, tpm *attest.TPM, ak *attest.AK, subject string, pcrs []int) error {
	if subject == "" {
		return fmt.Errorf("posture: attest needs a subject")
	}
	resp, err := conn.Request(natsx.SubjectAttestChallenge, []byte(subject), AttestTimeout)
	if err != nil {
		return fmt.Errorf("posture: attestation challenge: %w", err)
	}
	if len(resp.Data) == 0 {
		return fmt.Errorf("posture: attestation challenge returned no nonce (device not enrolled?)")
	}

	quote, err := tpm.Quote(ak, resp.Data, pcrs)
	if err != nil {
		return fmt.Errorf("posture: attestation quote: %w", err)
	}
	report, err := proto.Marshal(&corev1.AttestationReport{
		Subject:     subject,
		Nonce:       resp.Data,
		QuoteAttest: quote.Attest,
		QuoteSigR:   quote.SigR,
		QuoteSigS:   quote.SigS,
	})
	if err != nil {
		return fmt.Errorf("posture: marshalling attestation report: %w", err)
	}
	return conn.Publish(natsx.SubjectAttestReport, report)
}
