package gateway

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/policy"
)

// sigClassifier is a stand-in for the sandboxed worker's content-signature engine (proven in D221):
// it returns a CONTENT_SIGNATURE threat match when the classified payload contains the marker, so
// this test exercises the NIPS-1c WIRING (peek → Request.Body → classify → threat → policy → drop)
// without spawning a real worker.
type sigClassifier struct{ marker string }

func (s sigClassifier) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	resp := &corev1.ClassifyResponse{RequestId: req.GetRequestId(), EventId: req.GetEventId()}
	if strings.Contains(string(req.GetContent()), s.marker) {
		resp.ThreatMatches = []*corev1.ThreatMatch{{
			Category:    corev1.ThreatCategory_THREAT_CATEGORY_CONTENT_SIGNATURE,
			Confidence:  1.0,
			IndicatorId: "test-sig",
		}}
	}
	return resp, nil
}

type noopLedger struct{}

func (noopLedger) Append(context.Context, *core.Entry) error { return nil }
func (noopLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}
func (noopLedger) Close() error { return nil }

// blockOnThreatPolicy blocks a flow with any threat match, else allows.
func blockOnThreatPolicy(t *testing.T) core.Stage {
	t.Helper()
	pol, err := policy.New(context.Background(), "nips1c", "1", `package openshield
import rego.v1
has_threat if { input.threat; count(input.threat.matches) > 0 }
decision := {"action":"BLOCK","reason":"payload signature","confidence":0.9} if { has_threat }
decision := {"action":"ALLOW","reason":"clean","confidence":0.9} if { not has_threat }`)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

// TestTProxyPayloadSignatureBlocks proves the peeked cleartext payload is classified by the
// content-signature engine and a match drops the flow inline (NIPS-1 increment 3): the full
// peek → Request.Body → worker-classify → threat → policy → drop path.
//
// Mutation (the decider does not set Request.Body): the payload is not classified → no threat →
// the malicious flow is allowed → this test FAILs.
func TestTProxyPayloadSignatureBlocks(t *testing.T) {
	gw := New(sigClassifier{marker: "__MALWARE__"}, blockOnThreatPolicy(t), noopLedger{}, nil, 10*time.Second)
	srv := NewTProxyServer(gw, nil)

	origin := newEchoServer(t)
	client, peer := clientPair()
	defer peer.Close()
	go handleFlow(context.Background(), client, origin.ln.Addr(), srv.decide, srv.dial, nil)

	// The client's first bytes carry the malicious payload.
	go func() { _, _ = peer.Write([]byte("POST /x HTTP/1.1\r\n\r\n__MALWARE__ payload")) }()

	select {
	case <-origin.gotBytes:
		t.Fatal("the origin received the flow — a payload tripping a content signature must be dropped inline")
	case <-time.After(800 * time.Millisecond):
	}
}

// TestTProxyPayloadCleanSplices: a payload matching no signature is spliced to the origin.
func TestTProxyPayloadCleanSplices(t *testing.T) {
	gw := New(sigClassifier{marker: "__MALWARE__"}, blockOnThreatPolicy(t), noopLedger{}, nil, 10*time.Second)
	srv := NewTProxyServer(gw, nil)

	origin := newEchoServer(t)
	client, peer := clientPair()
	defer peer.Close()
	go handleFlow(context.Background(), client, origin.ln.Addr(), srv.decide, srv.dial, nil)

	go func() { _, _ = peer.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) }()

	select {
	case <-origin.gotBytes: // the clean flow reached the origin (spliced)
	case <-time.After(time.Second):
		t.Fatal("a clean payload was not spliced to the origin")
	}
}
