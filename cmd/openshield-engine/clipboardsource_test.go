package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/agent/worker"
	"github.com/lucianoengel/openshield/internal/classify"
	"github.com/lucianoengel/openshield/internal/clipboard"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
)

// seededCPF is a valid test CPF (check digits correct, so the REAL validator accepts it). It stands in for
// the sensitive thing a user copies.
const seededCPF = "111.444.777-35"

// scriptedReader is the OS seam, and the ONLY faked component in this test: the producer, the change
// detection, the content store, the engine, the classify stage and the CPF detector are all real.
type scriptedReader struct {
	contents []string
	calls    int
}

func (s *scriptedReader) Read(context.Context) ([]byte, error) {
	i := s.calls
	s.calls++
	if i >= len(s.contents) {
		i = len(s.contents) - 1
	}
	return []byte(s.contents[i]), nil
}

func (s *scriptedReader) DisplayServer() string { return clipboard.DisplayX11 }

// inProcessWorker runs the REAL classifier through the real worker handler, so a CPF hit here means the
// shipped detector chain actually fired on the clipboard bytes.
type inProcessWorker struct{ c *classify.Classifier }

func (w inProcessWorker) Classify(ctx context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	return worker.Handle(ctx, w.c, nil, req), nil
}

// recordingLedger captures appended entries; the engine requires a ledger.
type recordingLedger struct{ n int }

func (l *recordingLedger) Append(context.Context, *core.Entry) error { l.n++; return nil }
func (l *recordingLedger) Close() error                              { return nil }
func (l *recordingLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}

// TestClipboardCopyIsClassifiedAndTheEventCarriesNoContent is where DLP-2a's claim lives.
//
// A clipboard copy containing a CPF flows: scripted reader → real producer → real content store → real
// engine.Process → real worker + real classifier → policy. The assertions are the two properties that
// matter:
//
//  1. the CPF is DETECTED (so the content genuinely reached the sandboxed classifier), and
//  2. the SERIALIZED EVENT contains none of the copied text (so content never crossed onto the Event, D10).
//
// Mutation (i): put the clipboard text on the Event → assertion 2 FAILS.
// Mutation (ii): drop the store.Put registration → no CPF hit → assertion 1 FAILS.
func TestClipboardCopyIsClassifiedAndTheEventCarriesNoContent(t *testing.T) {
	copied := "please wire the payment, cpf " + seededCPF + ", thanks"

	// The producer, with only the OS seam faked.
	store := clipboard.NewContentStore(nil)
	events := make(chan *corev1.Event, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go clipboardSource(ctx, &scriptedReader{contents: []string{copied}}, store,
		10*time.Millisecond, events, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	var ev *corev1.Event
	select {
	case ev = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("the clipboard producer emitted no event")
	}

	// (2) The Event carries no content. Asserted on the SERIALIZED bytes, because that is what actually
	// leaves the process — a field-by-field check would miss content smuggled into an unexpected field.
	raw, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{seededCPF, "111444777", "wire the payment", copied} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("the serialized clipboard Event contains %q — clipboard content must never reach an "+
				"Event (D10/D29); it goes to the sandboxed worker only", secret)
		}
	}
	// The metadata IS there and is right.
	if ev.GetKind() != corev1.EventKind_EVENT_KIND_CLIPBOARD_COPY {
		t.Errorf("event kind = %v, want clipboard copy", ev.GetKind())
	}
	cb := ev.GetClipboard()
	if cb == nil {
		t.Fatal("the event carries no ClipboardSubject")
	}
	if got, want := int(cb.GetByteCount()), len(copied); got != want {
		t.Errorf("byte_count = %d, want %d", got, want)
	}
	if cb.GetDisplayServer() != clipboard.DisplayX11 {
		t.Errorf("display_server = %q, want x11", cb.GetDisplayServer())
	}

	// (1) Now run the REAL pipeline over that event, with the content resolver backed by the store the
	// producer registered into — exactly how cmd/openshield-engine wires it.
	var gotClassification *corev1.LocalClassification
	policy := stageFn("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		gotClassification = s.Classification
		return core.Decided(&corev1.Decision{
			DecisionId: "d-clip", EventId: s.Event.GetEventId(),
			Action: corev1.Action_ACTION_ALERT, Confidence: 0.9,
		}), nil
	})
	eng := engine.New(inProcessWorker{c: classify.New()}, policy, &recordingLedger{}, nil, 5*time.Second)
	eng.SetContentResolver(func(e *corev1.Event) []byte { return store.Resolve(e.GetEventId()) })

	dec, err := eng.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("processing the clipboard event: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Errorf("decision = %v, want ALERT", dec.GetAction())
	}
	if gotClassification == nil || len(gotClassification.GetMatches()) == 0 {
		t.Fatal("the clipboard content produced NO detector hits — the content never reached the " +
			"classifier (is the content registration wired?)")
	}
	var sawCPF bool
	for _, m := range gotClassification.GetMatches() {
		if m.GetDetectorType() == corev1.DetectorType_DETECTOR_TYPE_CPF {
			sawCPF = true
		}
	}
	if !sawCPF {
		t.Errorf("no CPF detector hit among %v — the seeded CPF was not detected in the copied text",
			gotClassification.GetMatches())
	}
	// And the content was RELEASED after resolution.
	if store.Len() != 0 {
		t.Errorf("content store retains %d entries after classification — it must release", store.Len())
	}
}

// TestClipboardProducerDoesNotReEmitUnchangedContent: an idle desktop must not alert once per interval.
//
// Mutation (v): ignore the change digest → repeated events → this FAILS.
func TestClipboardProducerDoesNotReEmitUnchangedContent(t *testing.T) {
	store := clipboard.NewContentStore(nil)
	events := make(chan *corev1.Event, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go clipboardSource(ctx, &scriptedReader{contents: []string{"same text forever"}}, store,
		5*time.Millisecond, events, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	// Long enough for many polls.
	time.Sleep(300 * time.Millisecond)
	cancel()
	if n := len(events); n != 1 {
		t.Fatalf("an unchanged clipboard emitted %d events over ~60 polls, want 1", n)
	}
}

// stageFn adapts a func to core.Stage for these tests.
type stageFnT struct {
	name string
	run  func(context.Context, *core.State) (core.Outcome, error)
}

func (s stageFnT) Name() string { return s.name }
func (s stageFnT) Run(ctx context.Context, st *core.State) (core.Outcome, error) {
	return s.run(ctx, st)
}

func stageFn(name string, run func(context.Context, *core.State) (core.Outcome, error)) core.Stage {
	return stageFnT{name: name, run: run}
}
