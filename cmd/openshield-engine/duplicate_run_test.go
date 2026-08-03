package main

import (
	"bytes"
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/worker"
	"github.com/lucianoengel/openshield/internal/classify"
	"github.com/lucianoengel/openshield/internal/clipboard"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/printguard"
)

// countingWorker counts how many times the pipeline actually asked the classifier to look at
// something, and whether each request carried content.
type countingWorker struct {
	c            *classify.Classifier
	calls        atomic.Int64
	withContent  atomic.Int64
	withoutBytes atomic.Int64
}

func (w *countingWorker) Classify(ctx context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	w.calls.Add(1)
	if len(req.GetContent()) > 0 {
		w.withContent.Add(1)
	} else {
		w.withoutBytes.Add(1)
	}
	return worker.Handle(ctx, w.c, nil, nil, req), nil
}

// TestOneJobIsOnePipelineRun (DLP-2) guards a defect the existing tests could not see, because they
// hand the decider a buffered channel WITH NO CONSUMER — and the production consumer is exactly what
// triggered it.
//
// printDecider both handed the event to the engine's observation loop (`events <- ev`) and ran
// eng.Process itself for the verdict, so one job ran the whole pipeline TWICE. That alone would be
// waste. What made it a security defect is that ContentStore.Resolve DELETES ON READ: only one of the
// two runs ever got the document, and the loser classified nothing. For a print job — whose entire
// content arrives out-of-band — "no content" yields an EMPTY classification rather than an error, so
// the blind run was indistinguishable from a genuinely clean document.
//
// When the observation loop won that race the blind run was the VERDICT: no CPF found, allow, and the
// payroll dump printed. A prevention control failing open, nondeterministically, silently. Reproduced
// before the fix: "a job containing a CPF was ALLOWED", with 2 ledger entries for one job.
//
// WHICH run wins is a race and is not testable. HOW MANY runs there are is deterministic, and that is
// the invariant: one job, one classification, one ledger entry.
//
// Mutation: run the pipeline a second time inside printDecider (which is what the removed
// `events <- ev` amounted to) → two classifications and two ledger entries → this FAILS.
func TestOneJobIsOnePipelineRun(t *testing.T) {
	job := []byte("%!PS\nEmployee record: CPF " + seededCPF + "\n")

	store := clipboard.NewContentStore(nil)
	w := &countingWorker{c: classify.New()}
	led := &recordingLedger{}

	var eventID string
	policy := stageFn("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		eventID = s.Event.GetEventId()
		action := corev1.Action_ACTION_ALLOW
		if s.Classification != nil && len(s.Classification.GetMatches()) > 0 {
			action = corev1.Action_ACTION_BLOCK
		}
		return core.Decided(&corev1.Decision{
			DecisionId: "d-" + s.Event.GetEventId(), EventId: s.Event.GetEventId(),
			Action: action, Confidence: 0.9, PolicyId: "t", PolicyVersion: "1"}), nil
	})
	eng := engine.New(w, policy, led, nil, 5*time.Second)
	eng.SetContentResolver(func(e *corev1.Event) []byte { return store.Resolve(e.GetEventId()) })

	ctx := context.Background()
	decide := printDecider(ctx, eng, store, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	v, err := decide(ctx, printguard.Request{
		ID: 1, Printer: "lobby-printer", User: "alice", HasTitle: true, Job: job,
	})
	if err != nil {
		t.Fatalf("deciding the print job: %v", err)
	}

	// THE VERDICT SEES THE DOCUMENT — the consequence that matters. With two runs racing for one-shot
	// content this failed whenever the observation loop won.
	if v != printguard.VerdictDeny {
		t.Errorf("a job containing a CPF was ALLOWED — the verdict path did not see the document "+
			"(classifier calls=%d, with content=%d, blind=%d)",
			w.calls.Load(), w.withContent.Load(), w.withoutBytes.Load())
	}
	if got := w.calls.Load(); got != 1 {
		t.Errorf("the classifier ran %d times for ONE print job, want 1", got)
	}
	if got := w.withContent.Load(); got != 1 {
		t.Errorf("%d classification(s) carried the document, want exactly 1", got)
	}
	if led.n != 1 {
		t.Errorf("the ledger recorded %d entries for ONE print job, want 1 — a hash-chained audit "+
			"trail whose value is saying what happened, once", led.n)
	}

	// WHY A SECOND RUN IS UNSAFE, asserted as a fact rather than left to a race: the store is
	// ONE-SHOT, so after the run that classified the job the bytes are gone. If this ever stops being
	// true, the invariant above stops protecting what its comment claims it protects.
	if b := store.Resolve(eventID); len(b) > 0 {
		t.Errorf("the content store still holds %d bytes for %s after classification — this test's "+
			"premise no longer holds", len(b), eventID)
	}
}

// TestASecondPipelineRunOverOneJobIsBlind states the hazard directly, so that removing the duplicate
// enqueue reads as a fix for a known failure rather than as a tidy-up.
//
// The clipboard mediator had the identical shape: OnCopy put the content, enqueued the event, and
// then called decide() — so a mediated copy also ran the pipeline twice, and when the loop won,
// sensitive content was not mediated and pasted anywhere.
func TestASecondPipelineRunOverOneJobIsBlind(t *testing.T) {
	store := clipboard.NewContentStore(nil)
	w := &countingWorker{c: classify.New()}

	var actions []corev1.Action
	policy := stageFn("policy", func(_ context.Context, s *core.State) (core.Outcome, error) {
		action := corev1.Action_ACTION_ALLOW
		if s.Classification != nil && len(s.Classification.GetMatches()) > 0 {
			action = corev1.Action_ACTION_BLOCK
		}
		actions = append(actions, action)
		return core.Decided(&corev1.Decision{
			DecisionId: "d", EventId: s.Event.GetEventId(),
			Action: action, Confidence: 0.9, PolicyId: "t", PolicyVersion: "1"}), nil
	})
	eng := engine.New(w, policy, &recordingLedger{}, nil, 5*time.Second)
	eng.SetContentResolver(func(e *corev1.Event) []byte { return store.Resolve(e.GetEventId()) })

	ev := printJobEvent(printguard.Request{ID: 7, Printer: "p", User: "alice"})
	store.Put(ev.GetEventId(), []byte("%!PS\nEmployee record: CPF "+seededCPF+"\n"))

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := eng.Process(ctx, ev); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}

	if len(actions) != 2 {
		t.Fatalf("expected two decisions, got %v", actions)
	}
	if actions[0] != corev1.Action_ACTION_BLOCK {
		t.Fatalf("the FIRST run did not see the document (%v) — the fixture is wrong", actions[0])
	}
	if actions[1] != corev1.Action_ACTION_ALLOW {
		t.Fatalf("the second run over the same job decided %v; expected ALLOW, because the content "+
			"store is one-shot and the second run therefore classifies nothing", actions[1])
	}
	// The giveaway: the blind run never even reached the worker, so there is no failed parse, no
	// error, and nothing in any log distinguishing it from a clean document.
	if got := w.calls.Load(); got != 1 {
		t.Errorf("classifier calls = %d, want 1 — the blind run is silent, which is what made this "+
			"defect invisible", got)
	}
}
