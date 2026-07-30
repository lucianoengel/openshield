package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
)

// syncBuffer is a concurrency-safe sink for the reporter's goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func runReporter(t *testing.T, m *core.Metrics, mutate func(), settle time.Duration) string {
	t.Helper()
	out := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); reportPipelineOutcomes(ctx, log, m, 20*time.Millisecond) }()

	time.Sleep(40 * time.Millisecond) // let the first tick establish a baseline
	mutate()
	time.Sleep(settle)

	cancel()
	<-done
	return out.String()
}

// A HEALTHY PIPELINE MUST SAY NOTHING. This is the whole reason the trigger set is not the reported set:
// Dispatched and Decided move on EVERY event, so triggering on "any counter moved" would log every
// interval forever on a working endpoint — the unconditional periodic line that gets filtered, turning a
// signal into a silence with extra steps (D348).
func TestAHealthyPipelineReportsNothing(t *testing.T) {
	var m core.Metrics
	got := runReporter(t, &m, func() {
		// Heavy, entirely successful traffic.
		for i := 0; i < 500; i++ {
			m.Dispatched.Add(1)
			m.Decided.Add(1)
		}
	}, 120*time.Millisecond)

	if strings.Contains(got, "pipeline stages are FAILING") {
		t.Fatalf("a pipeline that only dispatched and decided produced a warning; this line would fire "+
			"every interval on every healthy endpoint and be filtered out before the real one arrived:\n%s", got)
	}
}

// A TIMEOUT IS THE SIGNAL. "A rising timeout rate is its own signal: it is the cheapest way to detect an
// adversary manufacturing fail-open bypasses (D17)" — a stage that times out is answered fail-open, so
// those events were not decided on their merits.
func TestATimeoutIsReportedWithItsDenominator(t *testing.T) {
	var m core.Metrics
	m.Dispatched.Store(1000)
	m.Decided.Store(999)

	got := runReporter(t, &m, func() { m.TimedOut.Add(1) }, 120*time.Millisecond)

	if !strings.Contains(got, "pipeline stages are FAILING") {
		t.Fatalf("a timeout produced no report:\n%s", got)
	}
	// The denominator has to be there: "1 timeout" means nothing without how many were dispatched.
	for _, want := range []string{"timed_out=1", "dispatched=1000", "decided=999"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report omits %q — a rising timeout count is not interpretable without the "+
				"traffic it is a fraction of:\n%s", want, got)
		}
	}
}

func TestAFailureIsAlsoReported(t *testing.T) {
	var m core.Metrics
	got := runReporter(t, &m, func() { m.Failed.Add(1) }, 120*time.Millisecond)
	if !strings.Contains(got, "pipeline stages are FAILING") {
		t.Fatalf("a stage failure produced no report:\n%s", got)
	}
	if !strings.Contains(got, "failed=1") {
		t.Errorf("the report omits the failure count:\n%s", got)
	}
}

// Once the counters stop moving the reporter goes quiet again, or a single incident becomes a permanent
// warning nobody can clear and the next real one is invisible inside it.
func TestItGoesQuietAgainOnceTheFailuresStop(t *testing.T) {
	var m core.Metrics
	out := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); reportPipelineOutcomes(ctx, log, &m, 20*time.Millisecond) }()

	m.TimedOut.Add(1)
	time.Sleep(100 * time.Millisecond)
	firstCount := strings.Count(out.String(), "pipeline stages are FAILING")
	if firstCount == 0 {
		t.Fatal("the timeout was never reported")
	}

	// Nothing moves from here on.
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	if got := strings.Count(out.String(), "pipeline stages are FAILING"); got != firstCount {
		t.Fatalf("the reporter kept warning after the counters stopped moving (%d -> %d lines); a stuck "+
			"warning is one an operator learns to ignore", firstCount, got)
	}
}

// A nil Metrics is what an Engine with no dispatcher returns. The reporter must return rather than panic:
// this runs in its own goroutine in main, and a panic there takes down the whole engine.
func TestANilMetricsIsNotAPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		reportPipelineOutcomes(ctx, slog.New(slog.NewTextHandler(&syncBuffer{}, nil)), nil, time.Millisecond)
	}()
	select {
	case <-done: // returned immediately, as it must
	case <-time.After(2 * time.Second):
		t.Fatal("reportPipelineOutcomes(nil) did not return")
	}
}
