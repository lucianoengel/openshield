package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
)

// recordingWorker returns the configured hits and records the inline Content it was asked to
// classify, so a test can prove a body reached the worker via ClassifyRequest_Content.
type recordingWorker struct {
	hits        []*corev1.DetectorHit
	sawContent  []byte
	contentCall int
}

func (w *recordingWorker) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	if c := req.GetContent(); c != nil {
		w.sawContent = c
		w.contentCall++
	}
	return &corev1.ClassifyResponse{RequestId: req.GetRequestId(), EventId: req.GetEventId(), Hits: w.hits}, nil
}

func smtpEvent(id string) *corev1.Event {
	return &corev1.Event{
		EventId: id, Purpose: corev1.Purpose_PURPOSE_DLP, Kind: corev1.EventKind_EVENT_KIND_SMTP_MESSAGE,
		Target: &corev1.Event_Network{Network: &corev1.NetworkSubject{
			SniHost: "recipient.example", Protocol: "tcp", DstPort: 25}},
	}
}

// ENG-1: a network event that carries content (an SMTP body) is classified in the sandboxed worker
// via inline Content — the body reaches the worker WITHOUT entering the Event (D10/D29). A DNS event
// (no content) still skips content classification (D134), and a pathless file event still errors.
func TestNetworkContentClassifiedInWorker(t *testing.T) {
	fw := &recordingWorker{hits: []*corev1.DetectorHit{
		{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.95, Count: 1}}}
	var captured *corev1.LocalClassification
	capture := stageFunc("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		captured = s.Classification
		return core.Decided(&corev1.Decision{DecisionId: "d", EventId: s.Event.GetEventId(), Action: corev1.Action_ACTION_ALERT}), nil
	})
	led := &recLedger{}
	eng := engine.New(fw, capture, led, nil, time.Second)

	// The content resolver yields the SMTP body for the SMTP event and nothing for others (the SMTP
	// source will provide this once wired; here the test stands in for it).
	body := []byte("invoice, cpf 111.444.777-35, thanks")
	eng.SetContentResolver(func(ev *corev1.Event) []byte {
		if ev.GetKind() == corev1.EventKind_EVENT_KIND_SMTP_MESSAGE {
			return body
		}
		return nil
	})

	// SMTP body → classified in the worker via Content → CPF hit → decision + audit.
	dec, err := eng.Process(context.Background(), smtpEvent("smtp1"))
	if err != nil {
		t.Fatalf("SMTP event errored: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Errorf("no decision for the SMTP event: %v", dec)
	}
	if string(fw.sawContent) != string(body) {
		t.Errorf("worker saw content %q, want the SMTP body %q — the body did not reach the worker", fw.sawContent, body)
	}
	if captured == nil || len(captured.GetMatches()) != 1 ||
		captured.GetMatches()[0].GetDetectorType() != corev1.DetectorType_DETECTOR_TYPE_CPF {
		t.Fatalf("SMTP body classification = %v, want one CPF match", captured)
	}
	if captured.GetMatches()[0].GetMatchedText() != "" {
		t.Error("SMTP classification carried matched content — D29 boundary crossed")
	}
	if len(led.entries) == 0 {
		t.Error("no audit entry for the SMTP event")
	}

	// A DNS event carries no content: the resolver returns nil, so the worker is NOT given content
	// and the policy gets an empty classification (D134 preserved).
	fw.contentCall = 0
	if _, err := eng.Process(context.Background(), netEvent("dns1", "lookup.example")); err != nil {
		t.Fatalf("DNS event errored: %v", err)
	}
	if fw.contentCall != 0 {
		t.Errorf("worker was given content for a DNS event (%d calls) — metadata-only was violated", fw.contentCall)
	}
	if captured == nil || len(captured.GetMatches()) != 0 {
		t.Errorf("DNS classification = %v, want empty (content-free)", captured)
	}

	// A pathless file event still errors (D134 preserved).
	ev := &corev1.Event{
		EventId: "f0", Kind: corev1.EventKind_EVENT_KIND_FILE_MODIFIED,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: ""}}},
	}
	if _, err := eng.Process(context.Background(), ev); err == nil {
		t.Error("a pathless file event must still error")
	}
}
