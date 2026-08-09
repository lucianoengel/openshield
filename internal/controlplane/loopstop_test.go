package controlplane_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	"github.com/lucianoengel/openshield/internal/runner"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// logSink is a MUTEX-GUARDED slog destination.
//
// It exists because the tests below cancel a loop from inside a per-tick provider, and that provider runs
// on the LOOP's goroutine — so the line is written by a different goroutine than the one asserting on it.
// A bare bytes.Buffer shared that way is a genuine `-race` failure, not a theoretical one. Every test here
// still joins the loop before reading; the mutex is the second half of that discipline, not a substitute
// for it.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// newSinkLogger returns a logger writing into sink at Error level and above.
func newSinkLogger(sink *logSink) *slog.Logger {
	return slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestNoteTickErrCountsAndLogsIndependently: the shared helper's two decisions are SEPARATE.
//
// Counting and recording are different questions — not counting is about not paging, and not recording
// leaves an abandoned tick unexplainable afterwards (D31). This project has already conflated them once:
// the first version of the stop guard put the log inside the counting branch, so a database outage
// arriving during a shutdown produced no count AND no line.
//
// The table walks all four combinations of (live/cancelled loop context) × (cancellation/other error) and
// asserts BOTH halves every time — the counter delta and that a line came out carrying the right
// `stopping` value.
//
// Mutation A: make the log conditional on `!stopping` → the exempted-tick case FAILS on its log assertion.
// Mutation B: drop the `!stopping` condition on the increment → the stop case FAILS on its counter.
// Mutation C: widen isLoopStop to the context alone → "a real failure that lands while stopping" FAILS.
// Mutation D: remove the nil-logger default → the nil-logger case panics or FAILS.
func TestNoteTickErrCountsAndLogsIndependently(t *testing.T) {
	live := context.Background()
	stopped, cancel := context.WithCancel(context.Background())
	cancel()

	dbDown := errors.New("conn closed")

	for _, tc := range []struct {
		name         string
		ctx          context.Context
		err          error
		wantDelta    int64
		wantStopping bool
	}{
		// The one exemption: this loop's own context is gone AND the error IS that cancellation.
		{"the loop's own cancellation, while stopping", stopped, context.Canceled, 0, true},
		// leader.go cancels leaderCtx when its Postgres ping fails, so an outage yields a real driver
		// error and a cancellation in the same window. This case is why the predicate is a conjunction.
		{"a real failure that lands while stopping", stopped, dbDown, 1, false},
		{"a real failure on a live loop", live, dbDown, 1, false},
		// A cancellation on a LIVE loop is somebody else's abandoned work, not this loop stopping.
		{"a cancellation from elsewhere, loop still live", live, context.Canceled, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c atomic.Int64
			sink := &logSink{}
			controlplane.NoteTickErr(tc.ctx, newSinkLogger(sink), "test tick failed", &c, tc.err,
				slog.String("extra", "attr"))

			if got := c.Load(); got != tc.wantDelta {
				t.Errorf("counter moved by %d, want %d — the exemption is for this loop's own stop and "+
					"nothing else; counting a shutdown pages on a routine event, and exempting a real "+
					"error hides the outage the counter exists to report", got, tc.wantDelta)
			}

			line := sink.String()
			if line == "" {
				t.Fatalf("nothing was logged — a failing tick that is not counted is still a failing "+
					"tick, and the line is the only remaining trace that it was abandoned (D31). "+
					"stopping=%v", tc.wantStopping)
			}
			if want := "stopping=" + boolText(tc.wantStopping); !strings.Contains(line, want) {
				t.Errorf("line %q does not carry %q — a reader must be able to tell an exempted tick "+
					"from a counted one without inferring it from the counter", line, want)
			}
			if !strings.Contains(line, "test tick failed") {
				t.Errorf("line %q does not carry the message", line)
			}
			// The caller's own attributes survive alongside the stamp — the ITSM phase and the hunt
			// name are carried this way.
			if !strings.Contains(line, "extra=attr") {
				t.Errorf("line %q dropped the caller's attribute", line)
			}
			// LogAttrs, not log.Error: Error's variadic is `...any`, so slog.Attr values degrade to
			// `!BADKEY` and the stamp becomes unreadable. This is what catches that regression.
			if strings.Contains(line, "BADKEY") {
				t.Errorf("line %q contains !BADKEY — the helper is passing slog.Attr values to a "+
					"`...any` variadic (log.Error) instead of LogAttrs, so the stopping stamp is "+
					"not machine-readable", line)
			}
		})
	}

	// A loop handed NO logger still records, through the process-wide default. Every loop in
	// cmd/openshield-server was handed a literal nil before this change, so without this fallback the
	// whole logging requirement ships as a no-op the moment one call site is left empty.
	t.Run("a loop handed no logger still records", func(t *testing.T) {
		sink := &logSink{}
		prev := slog.Default()
		slog.SetDefault(newSinkLogger(sink))
		t.Cleanup(func() { slog.SetDefault(prev) })

		var c atomic.Int64
		controlplane.NoteTickErr(stopped, nil, "nil-logger tick failed", &c, context.Canceled)

		if got := c.Load(); got != 0 {
			t.Errorf("counter moved by %d on a stop, want 0", got)
		}
		line := sink.String()
		if !strings.Contains(line, "nil-logger tick failed") || !strings.Contains(line, "stopping=true") {
			t.Errorf("a nil logger dropped the record (got %q) — the fallback to slog.Default() is what "+
				"stops a caller's omission from silently deleting the only trace of an abandoned tick", line)
		}
	})
}

// ctxAwareHandler is a handler that HONOURS the context it is given, which slog explicitly permits and
// which buffered/network/OTel handlers actually do. It exists to make the WithoutCancel fix falsifiable:
// TextHandler ignores the context, so nothing else in this suite would notice the difference.
type ctxAwareHandler struct {
	slog.Handler
	dropped *atomic.Int64
}

func (h ctxAwareHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx.Err() != nil {
		h.dropped.Add(1)
		return nil // a real handler would drop, or fail to flush, on a dead context
	}
	return h.Handler.Handle(ctx, r)
}

// TestNoteTickErrDoesNotHandTheHandlerADeadContext.
//
// The ONLY lines whose context is cancelled are the EXEMPTED ones — that is what the exemption means. So
// a handler entitled to drop records on a dead context would delete precisely the lines the exemption
// depends on existing, leaving a counter that did not move and no explanation anywhere. That is the same
// structural shape as the `if log != nil` bug this change exists to fix: evidence that vanishes exactly
// when it is the only evidence.
//
// Mutation: pass `ctx` instead of `context.WithoutCancel(ctx)` to LogAttrs → the record is dropped and
// this FAILS.
func TestNoteTickErrDoesNotHandTheHandlerADeadContext(t *testing.T) {
	stopped, cancel := context.WithCancel(context.Background())
	cancel()

	sink := &logSink{}
	var dropped atomic.Int64
	log := slog.New(ctxAwareHandler{
		Handler: slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelError}),
		dropped: &dropped,
	})

	var c atomic.Int64
	controlplane.NoteTickErr(stopped, log, "exempted tick", &c, context.Canceled)

	if dropped.Load() != 0 {
		t.Errorf("the handler was handed a CANCELLED context and dropped %d record(s) — the exempted "+
			"lines are the only ones whose context is dead, so a context-honouring handler would erase "+
			"exactly the evidence the exemption relies on", dropped.Load())
	}
	if !strings.Contains(sink.String(), "exempted tick") {
		t.Errorf("the exempted line never reached the handler (got %q)", sink.String())
	}
}

// TestNoteTickErrIsLoudWhenGivenNoCounter. A nil counter is a programming error at the call site, and
// swallowing it would lose a real failure in exactly the way this helper exists to prevent. It does not
// panic — taking the control plane down from inside a logging helper is a worse outcome than a loud line.
//
// Mutation: return silently on a nil counter → this FAILS.
func TestNoteTickErrIsLoudWhenGivenNoCounter(t *testing.T) {
	sink := &logSink{}
	controlplane.NoteTickErr(context.Background(), newSinkLogger(sink), "a real failure", nil,
		errors.New("boom"))
	if line := sink.String(); !strings.Contains(line, "BUG") || !strings.Contains(line, "uncounted") {
		t.Errorf("a nil counter dropped a real failure quietly (got %q)", line)
	}
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// The per-loop stop tests below all share one seam and one discipline.
//
// THE SEAM: cancel from INSIDE a per-tick provider the loop itself calls. Cancelling from outside is
// vacuous — `retain.DynamicLoop` re-checks `ctx.Err()` after its timer and before invoking the work
// function, so an external cancel almost never lands mid-tick and the test passes without ever exercising
// the case it names. Waiting for the collision to happen by luck was tried in D485 and failed its own
// mutation 4 times in 10: flaky in the direction of PASSING.
//
// THE DISCIPLINE: that provider runs on the LOOP's goroutine. So every test here JOINS the loop
// (bounded, t.Fatal on timeout) BEFORE reading a counter or the log sink, and the sink is mutex-guarded.
// Reading either from the test goroutine without joining is a premature read and a genuine `-race`
// failure respectively. Counters are read as a before/after DELTA and never reset: they are package-level,
// another test's assertion depends on the absolute value, and resetting turns a cross-test leak into a
// silence.
//
// Each test asserts BOTH halves separately: the counter did not move AND a line came out saying the loop
// was stopping. They are separate decisions and conflating them is the defect D485 fixed.

// joinLoop waits for a loop goroutine to have returned, or fails the test.
func joinLoop(t *testing.T, done <-chan struct{}, cancel context.CancelFunc, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatalf("the %s loop did not return after its context was cancelled", name)
	}
}

// assertStopWasNotCounted is the shared two-halves assertion.
func assertStopWasNotCounted(t *testing.T, name string, before, after int64, line, wantMsg string) {
	t.Helper()
	if after != before {
		t.Errorf("stopping the %s loop counted %d failure(s) — losing leadership or shutting down is not "+
			"a failure of the work, and a counter that rises on a routine restart is a false alarm on the "+
			"metric that exists to say the work stopped happening", name, after-before)
	}
	if !strings.Contains(line, wantMsg) {
		t.Errorf("the %s loop's stopped tick logged nothing matching %q (got %q) — not counting is about "+
			"not paging; not RECORDING is a different decision, and an abandoned tick that leaves no "+
			"trace cannot be explained afterwards (D31)", name, wantMsg, line)
	}
	if !strings.Contains(line, "stopping=true") {
		t.Errorf("the %s loop's line does not say the loop was stopping (got %q) — without the stamp a "+
			"reader cannot tell an exempted tick from a counted one except by inferring it from the "+
			"counter, which is exactly what the line exists to avoid", name, line)
	}
}

// TestBeaconSweepStopIsNotAFailure — NIPS-6's sweep, cancelled inside `rule()`.
//
// `rule()` is evaluated in the argument list of `s.DetectBeaconing(c, rule(), s.now())`, so cancelling
// there means the very next thing that happens is a real sweep query under a cancelled context.
//
// Mutation A: have the loop count unconditionally (drop the `!stopping` guard in NoteTickErr) → the
// counter assertion FAILS. Mutation B: make the helper's log conditional on `!stopping` → the log
// assertion FAILS.
func TestBeaconSweepStopIsNotAFailure(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	now := time.Now().UTC()
	// Real telemetry, so the FIRST tick does real work and the second tick's queries are queries a
	// cancellation aborted — not a loop that had nothing to do.
	for i := 0; i < 20; i++ {
		seedFlow(t, srv, "subject-beacon-stop", "c2.stop.example", now.Add(-time.Duration(20-i)*time.Minute), true)
	}

	before := controlplane.BeaconFailures.Load()
	sink := &logSink{}
	loopCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var ticks int
	go func() {
		defer close(done)
		srv.RunBeaconLoop(loopCtx,
			func() time.Duration { return time.Millisecond },
			func() controlplane.BeaconRule {
				if ticks++; ticks == 2 {
					cancel()
				}
				return controlplane.BeaconRule{Window: 2 * time.Hour}
			}, newSinkLogger(sink))
	}()
	joinLoop(t, done, cancel, "beacon")

	assertStopWasNotCounted(t, "beacon", before, controlplane.BeaconFailures.Load(),
		sink.String(), "beaconing sweep failed")
}

// TestPlaybookTickStopIsNotAFailure — SOAR-4's executor, cancelled inside `playbooks()`.
//
// The slice returned is NON-EMPTY on purpose: the loop takes an early `return` when `len(pbs) == 0`, so
// an empty one would skip the work entirely and the test would assert that a tick which did nothing
// counted nothing.
func TestPlaybookTickStopIsNotAFailure(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	seedIncident(t, pool, "cross_domain", "subject-pb-stop", 0.96, []string{"dlp"})
	pb := firstResponse()

	before := controlplane.PlaybookFailures.Load()
	sink := &logSink{}
	loopCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var ticks int
	go func() {
		defer close(done)
		srv.RunPlaybookLoop(loopCtx,
			func() time.Duration { return time.Millisecond },
			func() []controlplane.Playbook {
				if ticks++; ticks == 2 {
					cancel()
				}
				return []controlplane.Playbook{pb}
			}, newSinkLogger(sink))
	}()
	joinLoop(t, done, cancel, "playbook")

	assertStopWasNotCounted(t, "playbook", before, controlplane.PlaybookFailures.Load(),
		sink.String(), "playbook tick failed")
}

// TestEscalationSweepStopIsNotAFailure — SOAR-9b's sweep, cancelled inside `ladder()`.
//
// THE LADDER MUST HAVE AT LEAST ONE RUNG. `Escalate` returns `(0, nil)` immediately when
// `len(l.Rungs) == 0`, so an empty ladder means no query runs, no error is produced, and the test passes
// while proving nothing.
//
// Mutation: return an empty `controlplane.Ladder{}` → the test must FAIL, because there is then nothing
// to exempt. That is what proves the seam is live rather than the assertion being trivially true.
func TestEscalationSweepStopIsNotAFailure(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	seedIncident(t, pool, "cross_domain", "subject-esc-stop", 0.96, []string{"dlp"})

	before := controlplane.EscalationFailures.Load()
	sink := &logSink{}
	loopCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var ticks int
	go func() {
		defer close(done)
		srv.RunEscalationLoop(loopCtx,
			func() time.Duration { return time.Millisecond },
			func() controlplane.Ladder {
				if ticks++; ticks == 2 {
					cancel()
				}
				return controlplane.Ladder{Rungs: []controlplane.Rung{
					{After: time.Minute, AfterSeconds: 60, Sinks: []string{"pager"}},
				}}
			}, newSinkLogger(sink))
	}()
	joinLoop(t, done, cancel, "escalation")

	assertStopWasNotCounted(t, "escalation", before, controlplane.EscalationFailures.Load(),
		sink.String(), "incident escalation sweep failed")
}

// TestApprovalExpiryStopIsNotAFailureAndIsLogged — SOAR-3's expiry sweep.
//
// This loop has NO provider inside its work function, so the seam is the interval provider itself:
// `DynamicLoop` calls `next()` TWICE per iteration, and the second call happens AFTER its `ctx.Err()`
// guard — so cancelling there is the one place that deterministically lands inside the tick. Call 4 is
// the second call of the second iteration, which leaves the first tick to do real work.
//
// THE LOG HALF HERE IS A NEW CAPABILITY, not a regression guard: RunApprovalExpiryLoop had no logger
// parameter at all and counted ApprovalExpiryFailures with no line whatsoever.
//
// The sub-test with a nil logger is the other half of the spec's guarantee, and is falsifiable on its
// own: a loop handed NO logger must still record, through slog.Default(). Mutation: remove the nil
// fallback from NoteTickErr → the line disappears and it FAILS.
func TestApprovalExpiryStopIsNotAFailureAndIsLogged(t *testing.T) {
	run := func(t *testing.T, useNilLogger bool) {
		t.Helper()
		pool := requireDB(t)
		srv := controlplane.New(pool)

		sink := &logSink{}
		var passed *slog.Logger
		if useNilLogger {
			// The fallback path: nothing is passed, so the record has to reach the process default.
			prev := slog.Default()
			slog.SetDefault(newSinkLogger(sink))
			t.Cleanup(func() { slog.SetDefault(prev) })
		} else {
			passed = newSinkLogger(sink)
		}

		before := controlplane.ApprovalExpiryFailures.Load()
		loopCtx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var calls int
		go func() {
			defer close(done)
			srv.RunApprovalExpiryLoop(loopCtx, func() time.Duration {
				// 1,2 = first iteration (2 runs the first tick); 3,4 = second. Cancelling on 4 is
				// past DynamicLoop's ctx.Err() guard, so the tick runs on a cancelled context.
				if calls++; calls == 4 {
					cancel()
				}
				return time.Millisecond
			}, passed)
		}()
		joinLoop(t, done, cancel, "approval expiry")

		assertStopWasNotCounted(t, "approval expiry", before,
			controlplane.ApprovalExpiryFailures.Load(), sink.String(), "approval expiry sweep failed")
	}

	t.Run("with the logger the server passes", func(t *testing.T) { run(t, false) })
	t.Run("with no logger at all, via slog.Default", func(t *testing.T) { run(t, true) })
}

// TestITSMSyncStopIsNotAFailure — SOAR-8(a)'s sync, cancelled from inside the remote system's handler.
//
// The connector's MinSeverity is LOW and the incident's risk is high, so the incident genuinely reaches
// the create path. Getting that wrong is not a small mistake: `severityFloor` rejects an unknown severity
// with a plain error, the loop counts it, and the test then passes for entirely the wrong reason.
//
// The handler cancels and then BLOCKS on `<-r.Context().Done()`, so the in-flight POST fails
// deterministically with a `*url.Error` wrapping `context.Canceled` — no sleep, no luck.
//
// It also asserts the line NAMES THE INTERRUPTED PHASE. The exemption is about not paging, not about the
// work being safe: ticket creation is a remote POST followed by a local link row, so the loop has to be
// able to say which half was interrupted rather than emitting an undifferentiated "itsm sync failed".
func TestITSMSyncStopIsNotAFailure(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	seedIncident(t, pool, "cross_domain", "subject-itsm-stop", 0.96, []string{"dlp"})

	loopCtx, cancel := context.WithCancel(context.Background())
	var hits atomic.Int64
	// `release` un-parks the handler at the end of the test. The handler must NOT answer the POST — a
	// 2xx would make this a test of a healthy sync — but it also must not park forever: the client
	// aborts on the cancelled context without ever closing the request body, so the server never
	// notices the disconnect and `httptest.Server.Close` (which waits for outstanding handlers) hangs.
	// Waiting on r.Context() ALONE deadlocked the test for exactly that reason.
	release := make(chan struct{})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		cancel()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	// LIFO: release the handler FIRST, then close the server — including on a t.Fatal above.
	defer remote.Close()
	defer close(release)

	before := controlplane.ITSMFailures.Load()
	sink := &logSink{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.RunITSMLoop(loopCtx, time.Millisecond, &runner.ITSMConnector{
			Name: "stop-test", Endpoint: remote.URL, MinSeverity: controlplane.SeverityLow,
			ClosedStatuses: []string{"closed"}, Timeout: 30 * time.Second,
		}, newSinkLogger(sink))
	}()
	joinLoop(t, done, cancel, "itsm")

	if hits.Load() == 0 {
		t.Fatal("the sync never reached the remote system — the incident did not reach the create path, " +
			"so this test would be asserting that a tick which did no remote work counted nothing")
	}
	line := sink.String()
	assertStopWasNotCounted(t, "itsm", before, controlplane.ITSMFailures.Load(), line, "itsm sync failed")
	if !strings.Contains(line, "phase=") {
		t.Errorf("the itsm stop line names no phase (got %q) — ticket creation leaves state in somebody "+
			"else's system, so which half was interrupted is the actionable part of the record", line)
	}
}

// TestCalleeCountersRouteThroughTheHelper — the counters a loop moves through a FUNCTION IT CALLS.
//
// The build-time guard is lexical: it sees a `*Failures.Add` inside a loop literal and cannot see one
// inside a method called from it. The spec says so explicitly and binds those writes anyway ("a loop's
// transitive writes are part of its stop behaviour and SHALL be brought through the helper when found").
// Three were found by review after the first pass:
//
//   - RecordUnifiedAlert (reached from RunBeaconLoop via DetectBeaconing, which swallowed the error with
//     `continue`, so a cancellation during alert recording reached NO log at all while
//     UnifiedAlertFailures rose once per detected beacon on every leader handover);
//   - linkRecurrence's two call sites in MaterializeIncidents and MaterializeCrossDomainIncidents, both
//     inside RunCorrelationLoop's tick, both counting unconditionally with no log call whatsoever.
//
// THE FAULTS ARE INJECTED BY DAMAGING THE SCHEMA, because there is no other deterministic way in: these
// paths fail only when the database refuses them. requireDB drops and re-migrates for every test, so the
// damage does not outlive this one.
func TestCalleeCountersRouteThroughTheHelper(t *testing.T) {
	t.Run("a unified alert recorded during a stop is not counted, and still logged", func(t *testing.T) {
		pool := requireDB(t)
		srv := controlplane.New(pool)
		sink := &logSink{}
		prev := slog.Default()
		slog.SetDefault(newSinkLogger(sink))
		t.Cleanup(func() { slog.SetDefault(prev) })

		before := srv.UnifiedAlertFailures.Load()
		stopped, cancel := context.WithCancel(context.Background())
		cancel()
		err := srv.RecordUnifiedAlert(stopped, controlplane.AlertRecord{
			Domain: "nips", SubjectKind: xdr.KindDevice, Subject: "subject-callee-stop",
			Severity: controlplane.SeverityMedium, Title: "network beaconing",
			DedupKey: "beacon:callee:stop:60s", DetectedAt: time.Now(),
		})
		if err == nil {
			t.Fatal("recording under a cancelled context succeeded — nothing was exempted and this " +
				"test proves nothing")
		}
		if got := srv.UnifiedAlertFailures.Load(); got != before {
			t.Errorf("a stop counted %d unified-alert failure(s) — openshield_unified_alert_failures_total "+
				"means 'projections that could not be recorded', and it used to jump by one per detected "+
				"beacon on every leader handover", got-before)
		}
		if line := sink.String(); !strings.Contains(line, "recording a unified alert failed") ||
			!strings.Contains(line, "stopping=true") {
			t.Errorf("the exempted recording left no stamped line (got %q). This path was the worst of "+
				"the three: DetectBeaconing swallows the error, so without a line here the drop was "+
				"completely invisible", line)
		}
	})

	t.Run("a real unified-alert failure on a live loop is still counted and logged", func(t *testing.T) {
		pool := requireDB(t)
		srv := controlplane.New(pool)
		sink := &logSink{}
		prev := slog.Default()
		slog.SetDefault(newSinkLogger(sink))
		t.Cleanup(func() { slog.SetDefault(prev) })

		// The negative above is only meaningful against a path that DOES count when it should.
		if _, err := pool.Exec(context.Background(), `DROP TABLE unified_alerts CASCADE`); err != nil {
			t.Fatal(err)
		}
		before := srv.UnifiedAlertFailures.Load()
		if err := srv.RecordUnifiedAlert(context.Background(), controlplane.AlertRecord{
			Domain: "nips", SubjectKind: xdr.KindDevice, Subject: "subject-callee-live",
			Severity: controlplane.SeverityMedium, Title: "network beaconing",
			DedupKey: "beacon:callee:live:60s", DetectedAt: time.Now(),
		}); err == nil {
			t.Fatal("recording into a dropped table succeeded")
		}
		if got := srv.UnifiedAlertFailures.Load(); got != before+1 {
			t.Errorf("a real failure moved the counter by %d, want 1", got-before)
		}
		if line := sink.String(); !strings.Contains(line, "stopping=false") {
			t.Errorf("a counted failure was not stamped as a non-stop (got %q)", line)
		}
	})

	t.Run("a recurrence-link failure is counted AND logged", func(t *testing.T) {
		pool := requireDB(t)
		srv := controlplane.New(pool)
		srv.SetNotifier(&countingSink{})
		sink := &logSink{}
		prev := slog.Default()
		slog.SetDefault(newSinkLogger(sink))
		t.Cleanup(func() { slog.SetDefault(prev) })

		// linkRecurrence UPDATEs recurrence_of/recurrence_count; the materializer's INSERT names neither,
		// so dropping the column lets the incident insert succeed and fails ONLY the link — which is the
		// one path this sub-test is about.
		if _, err := pool.Exec(context.Background(),
			`ALTER TABLE incidents DROP COLUMN recurrence_of CASCADE`); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		subject := pseudonym.Of("agent-recurrence-callee")
		recordAlert(t, srv, "hips", subject, controlplane.SeverityHigh, now.Add(-4*time.Minute))
		recordAlert(t, srv, "nips", subject, controlplane.SeverityHigh, now.Add(-2*time.Minute))

		before := controlplane.RecurrenceLinkFailures.Load()
		// The CROSS-DOMAIN materializer, which is also the site that runs once PER CONFIGURED HUNT — so
		// the old unconditional increment moved this counter by the number of hunts on every demotion.
		if _, err := srv.MaterializeCrossDomainIncidents(context.Background(),
			controlplane.CrossDomainRule{Window: 30 * time.Minute, MinDomains: 2}, now); err != nil {
			t.Fatalf("materialization itself failed, so the link was never reached: %v", err)
		}
		if got := controlplane.RecurrenceLinkFailures.Load(); got != before+1 {
			t.Fatalf("the link failure moved the counter by %d, want 1 — if 0, the fault injection no "+
				"longer reaches linkRecurrence and this sub-test proves nothing", got-before)
		}
		// THE HALF THAT WAS MISSING ENTIRELY: this site had no log call at all, so
		// openshield_recurrence_link_failures_total moved with nothing anywhere explaining it.
		if line := sink.String(); !strings.Contains(line, "linking an incident to the one it recurs from failed") ||
			!strings.Contains(line, "stopping=false") || !strings.Contains(line, "kind=cross_domain") {
			t.Errorf("the recurrence-link failure produced no usable line (got %q)", line)
		}
	})
}

// TestAnOrphanedTicketIsReportedAsOne — every branch that leaves a ticket in somebody else's queue with
// no local link says so, and the merely-ambiguous one says it is ambiguous.
//
// The first pass raised ErrTicketUnlinked for exactly ONE of the three orphaning branches (a failed
// INSERT after a good create) and let the other two fall through to `phase=opening_tickets`, whose
// documented meaning is that an interrupted open "leaves nothing behind — the next tick re-reads". An
// on-call engineer reads that as harmless. The truth for those two is a duplicate ticket every tick,
// forever, because the next tick's `NOT EXISTS` re-selects the same incident.
//
// Mutation: drop the ErrTicketCreatedUnknownRef mapping in openTickets → both 2xx cases fall back to
// ErrTicketOpening → the first two sub-tests FAIL.
func TestAnOrphanedTicketIsReportedAsOne(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	seedIncident(t, pool, "cross_domain", "subject-orphan", 0.96, []string{"dlp"})

	for _, tc := range []struct {
		name      string
		handler   http.HandlerFunc
		wantIs    error
		wantPhase string
	}{
		{
			// 2xx, then a body that will not decode. The ticket EXISTS.
			name: "the remote system accepted the create and returned an undecodable body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"ref": <<not json>>}`))
			},
			wantIs: controlplane.ErrTicketUnlinked, wantPhase: "ticket_created_not_linked",
		},
		{
			// 2xx with no reference. Its own error message already said the ticket could not be linked.
			name: "the remote system accepted the create and returned no reference",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"url":"https://tickets.example/1"}`))
			},
			wantIs: controlplane.ErrTicketUnlinked, wantPhase: "ticket_created_not_linked",
		},
		{
			// A non-2xx IS the remote system declining: nothing was created, the next tick retries.
			name:      "a refused create leaves nothing behind",
			handler:   func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", http.StatusBadRequest) },
			wantIs:    controlplane.ErrTicketOpening,
			wantPhase: "opening_tickets",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote := httptest.NewServer(tc.handler)
			defer remote.Close()
			err := srv.SyncITSM(context.Background(), &runner.ITSMConnector{
				Name: "orphan-test", Endpoint: remote.URL, MinSeverity: controlplane.SeverityLow,
				ClosedStatuses: []string{"closed"}, Timeout: 5 * time.Second,
			})
			if err == nil {
				t.Fatal("the sync succeeded; there is nothing to classify")
			}
			if !errors.Is(err, tc.wantIs) {
				t.Errorf("err = %v, want errors.Is(..., %v). Reporting an orphaned remote ticket as an "+
					"ordinary interrupted open tells a responder it is harmless when it duplicates "+
					"forever", err, tc.wantIs)
			}
			sink := &logSink{}
			controlplane.NoteTickErr(context.Background(), newSinkLogger(sink), "itsm sync failed",
				&controlplane.ITSMFailures, err, controlplane.ITSMPhaseForTest(err)...)
			if line := sink.String(); !strings.Contains(line, "phase="+tc.wantPhase) {
				t.Errorf("line %q does not carry phase=%s", line, tc.wantPhase)
			}
			// ONE KEY, ONE TYPE. Both unreconciled branches emit `remote_state_unreconciled`, and a
			// bool in one against a string in the other is a type conflict a JSON handler feeding a
			// strict-mapping sink rejects outright — dropping precisely the two lines that carry the
			// duplicate-ticket warning. Asserted here rather than left to review because the branches
			// are written apart and read apart.
			if line := sink.String(); strings.Contains(line, "remote_state_unreconciled=") &&
				!strings.Contains(line, "remote_state_unreconciled=yes") &&
				!strings.Contains(line, "remote_state_unreconciled=unknown") {
				t.Errorf("line %q carries remote_state_unreconciled with a value outside {yes,unknown}; "+
					"a second type on this key makes a strict-mapping log sink drop the line", line)
			}
		})
	}

	// The genuinely UNKNOWN case: the transport fails after the body was sent, so the far side may or may
	// not hold a ticket. Claiming either certainty is worse than saying so — one answer sends a responder
	// hunting a ticket that is usually not there, the other hides the one that is.
	t.Run("an interrupted create is reported as ambiguous, not as certain", func(t *testing.T) {
		remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Skip("no hijacker")
			}
			c, _, err := hj.Hijack() // kill the connection mid-request: a transport failure, not a status
			if err == nil {
				_ = c.Close()
			}
		}))
		defer remote.Close()
		err := srv.SyncITSM(context.Background(), &runner.ITSMConnector{
			Name: "orphan-ambiguous", Endpoint: remote.URL, MinSeverity: controlplane.SeverityLow,
			ClosedStatuses: []string{"closed"}, Timeout: 5 * time.Second,
		})
		if err == nil {
			t.Fatal("the sync succeeded")
		}
		if !errors.Is(err, controlplane.ErrTicketMaybeUnlinked) {
			t.Errorf("err = %v, want errors.Is(..., ErrTicketMaybeUnlinked)", err)
		}
		if errors.Is(err, controlplane.ErrTicketUnlinked) {
			t.Error("an ambiguous transport failure was reported as a CERTAIN orphan — the two call for " +
				"opposite responses and collapsing them is how a real report gets ignored next time")
		}
	})

	// A configuration fault is not an interrupted operation, and must not borrow a phase that never ran.
	t.Run("a bad MinSeverity is reported as configuration, not as an interrupted open", func(t *testing.T) {
		err := srv.SyncITSM(context.Background(), &runner.ITSMConnector{
			Name: "orphan-config", Endpoint: "http://127.0.0.1:1", MinSeverity: "not-a-severity",
		})
		if !errors.Is(err, controlplane.ErrTicketConfig) {
			t.Fatalf("err = %v, want errors.Is(..., ErrTicketConfig)", err)
		}
		sink := &logSink{}
		controlplane.NoteTickErr(context.Background(), newSinkLogger(sink), "itsm sync failed",
			&controlplane.ITSMFailures, err, controlplane.ITSMPhaseForTest(err)...)
		if line := sink.String(); !strings.Contains(line, "phase=configuration") {
			t.Errorf("line %q claims a phase that never ran", line)
		}
	})
}
