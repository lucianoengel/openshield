package gateway_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
)

// markerWorker reports a CPF hit only when the classified content contains marker —
// so a request/response is "sensitive" iff it carries the marker, and the gzip test
// can tell decoded content (marker present) from compressed bytes (absent).
type markerWorker struct{ marker string }

func (m markerWorker) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	var hits []*corev1.DetectorHit
	if bytes.Contains(req.GetContent(), []byte(m.marker)) {
		hits = cpfHit()
	}
	return &corev1.ClassifyResponse{RequestId: req.GetRequestId(), EventId: req.GetEventId(), Hits: hits}, nil
}

// blockOnHit BLOCKs when classification has any hit, else ALLOWs — so a ledger
// entry's action reveals whether that body was found sensitive.
func blockOnHit(t *testing.T) core.Stage {
	t.Helper()
	pol, err := policy.New(context.Background(), "nips4", "1", `package openshield
import rego.v1
hit if { some m in input.classification; m.count > 0 }
decision := {"action":"BLOCK","reason":"sensitive","confidence":0.9} if { hit }
decision := {"action":"ALLOW","reason":"clean","confidence":0.9} if { not hit }`)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

// respUpstream returns an upstream that replies with the given body/headers.
func respUpstream(t *testing.T, body []byte, header map[string]string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

const respMarker = "SENSITIVE-CPF-111.444.777-35"

func lastAction(entries []*core.Entry) corev1.Action {
	if len(entries) == 0 {
		return corev1.Action_ACTION_UNSPECIFIED
	}
	return entries[len(entries)-1].Decision.GetAction()
}

// TestResponseInspectionClassifiesAndDelivers: inspection ON, a marker in the
// RESPONSE is classified (an extra ledger entry, action BLOCK) and the client still
// gets the exact upstream body.
func TestResponseInspectionClassifiesAndDelivers(t *testing.T) {
	up := respUpstream(t, []byte("report: "+respMarker+" end"), nil)
	led := &recLedger{}
	gw := gateway.New(markerWorker{marker: respMarker}, blockOnHit(t), led, nil, time.Second)
	p := gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, false, nil)
	p.SetInspectResponses(true)
	proxyURL := serveProxy(t, p)

	// A CLEAN request (no marker) so only the response drives a sensitive verdict.
	resp, err := proxyClient(t, proxyURL).Post(up.URL, "text/plain", strings.NewReader("clean request body"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if !bytes.Contains(got, []byte(respMarker)) {
		t.Fatalf("client did not receive the upstream body: %q", got)
	}
	// Two ledger entries: the (clean) request ALLOW and the (sensitive) response BLOCK.
	if len(led.entries) != 2 {
		t.Fatalf("ledger entries = %d, want 2 (request + response)", len(led.entries))
	}
	if lastAction(led.entries) != corev1.Action_ACTION_BLOCK {
		t.Fatalf("response decision = %v, want BLOCK (the response marker was classified)", lastAction(led.entries))
	}
}

// TestResponseInspectionGunzips: a gzip-encoded response is DECODED before
// classification, so the marker inside is found (response BLOCK).
func TestResponseInspectionGunzips(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("data " + respMarker + " tail"))
	_ = zw.Close()

	up := respUpstream(t, buf.Bytes(), map[string]string{"Content-Encoding": "gzip"})
	led := &recLedger{}
	gw := gateway.New(markerWorker{marker: respMarker}, blockOnHit(t), led, nil, time.Second)
	p := gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, false, nil)
	p.SetInspectResponses(true)
	proxyURL := serveProxy(t, p)

	resp, err := proxyClient(t, proxyURL).Post(up.URL, "text/plain", strings.NewReader("clean"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The gzip body was decoded, the marker found → the response entry is BLOCK.
	if lastAction(led.entries) != corev1.Action_ACTION_BLOCK {
		t.Fatalf("gzip response decision = %v, want BLOCK (decoded content should match)", lastAction(led.entries))
	}
}

// TestResponseInspectionOverCapDeliversIntact: a response over the cap is delivered
// byte-for-byte and recorded as an uninspected gap, not truncated or refused.
func TestResponseInspectionOverCapDeliversIntact(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 500)
	up := respUpstream(t, big, nil)
	led := &recLedger{}
	gw := gateway.New(markerWorker{marker: respMarker}, blockOnHit(t), led, nil, time.Second)
	p := gateway.NewProxy(gw, gateway.NewTable(), nil, "", 100 /* small cap */, false, nil)
	p.SetInspectResponses(true)
	proxyURL := serveProxy(t, p)

	resp, err := proxyClient(t, proxyURL).Post(up.URL, "text/plain", strings.NewReader("clean"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if !bytes.Equal(got, big) {
		t.Fatalf("over-cap response was not delivered intact: got %d bytes, want %d", len(got), len(big))
	}
}

// TestResponseInspectionOffUnchanged: with inspection OFF the response is streamed
// through with NO response classification entry (request only).
func TestResponseInspectionOffUnchanged(t *testing.T) {
	up := respUpstream(t, []byte("report: "+respMarker+" end"), nil)
	led := &recLedger{}
	gw := gateway.New(markerWorker{marker: respMarker}, blockOnHit(t), led, nil, time.Second)
	p := gateway.NewProxy(gw, gateway.NewTable(), nil, "", 0, false, nil) // inspection OFF (default)
	proxyURL := serveProxy(t, p)

	resp, err := proxyClient(t, proxyURL).Post(up.URL, "text/plain", strings.NewReader("clean request"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if !bytes.Contains(got, []byte(respMarker)) {
		t.Fatal("client did not receive the upstream body")
	}
	if len(led.entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1 (request only — no response inspection)", len(led.entries))
	}
}
