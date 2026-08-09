package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/config"
	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/runner"
)

// wiringSink is a mutex-guarded log destination. The seven loops write from seven goroutines.
type wiringSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *wiringSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *wiringSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestServerWiresALoggerIntoEveryLeaderLoop drives the REAL startup seam and asserts that every scheduled
// leader loop this binary starts writes through the logger this binary built.
//
// WHY THIS TEST EXISTS. Before this change `cmd/openshield-server` did not import log/slog at all: all
// seven loops were handed a literal `nil`, every log call in every loop body was wrapped in
// `if log != nil`, and D485's "a failing tick is logged even when it is not counted" had therefore never
// emitted a single line from the shipped binary. That defect COMPILES. A requirement written against a
// function signature is one production satisfies with `nil`, so the only assertion worth making is that
// a line comes out of the process.
//
// It is modelled on cmd/openshield-engine/enforce_wiring_test.go, which works for the same reason this
// one now can: the wiring is a factored function (`startLeaderLoops`) rather than 500 inline lines.
//
// HOW A FAILING TICK IS FORCED, without a database: the pool points at a closed port, so every query
// every loop makes returns an error on its first tick. That is a real error travelling the real path —
// not an injected one.
//
// slog's DEFAULT is deliberately pointed at io.Discard. controlplane.NoteTickErr falls back to
// slog.Default() when handed nil, so leaving the default pointed at this test's sink would make the
// mutation below pass: a call site reverted to `nil` would still land in the sink. Discarding the default
// is what makes "was this call site wired?" the actual question.
//
// Mutation: revert ANY ONE of the seven call sites in startLeaderLoops to `nil` → that loop's line goes
// to the discarded default instead of the sink, and this FAILS naming that loop.
func TestServerWiresALoggerIntoEveryLeaderLoop(t *testing.T) {
	// Dynamic settings are read from the database, never from the environment — except through the
	// declared break-glass door, which is how a test drives them without one.
	dynamic := map[string]string{
		"OPENSHIELD_CORRELATE_INTERVAL":       "10ms",
		"OPENSHIELD_CORRELATE_WINDOW":         "1h",
		"OPENSHIELD_CORRELATE_MIN_ALERTS":     "2",
		"OPENSHIELD_CORRELATE_MIN_DOMAINS":    "2",
		"OPENSHIELD_BEACON_INTERVAL":          "10ms",
		"OPENSHIELD_BEACON_WINDOW":            "1h",
		"OPENSHIELD_APPROVAL_EXPIRY_INTERVAL": "10ms",
		"OPENSHIELD_PLAYBOOK_INTERVAL":        "10ms",
		"OPENSHIELD_ESCALATION_INTERVAL":      "10ms",
		"OPENSHIELD_RETENTION_INTERVAL":       "10ms",
	}
	var keys []string
	for k, v := range dynamic {
		t.Setenv(k, v)
		keys = append(keys, k)
	}

	dir := t.TempDir()
	playbooks := filepath.Join(dir, "playbooks.json")
	if err := os.WriteFile(playbooks, []byte(
		`[{"name":"wiring","trigger":{"min_severity":"low"},"steps":[{"step":"enrich"}]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	ladder := filepath.Join(dir, "ladder.json")
	if err := os.WriteFile(ladder, []byte(
		`{"rungs":[{"after_seconds":600,"sinks":["pager"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENSHIELD_PLAYBOOKS", playbooks)
	t.Setenv("OPENSHIELD_ESCALATION_LADDER", ladder)
	keys = append(keys, "OPENSHIELD_PLAYBOOKS", "OPENSHIELD_ESCALATION_LADDER")
	t.Setenv(config.BreakGlassEnv, strings.Join(keys, ","))

	// A pool whose every query fails immediately: connect_timeout keeps a stalled dial from turning a
	// wiring assertion into a timeout, and port 1 is refused outright.
	pool, err := pgxpool.New(context.Background(),
		"postgres://nobody:nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	sink := &wiringSink{}
	log := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelError}))
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startLeaderLoops(ctx, srv, serverConfig(), log, leaderDeps{
		itsm: &runner.ITSMConnector{
			Name: "wiring", Endpoint: "http://127.0.0.1:1", MinSeverity: controlplane.SeverityHigh,
			Timeout: time.Second,
		},
		itsmInterval: 10 * time.Millisecond,
		escalation:   true,
		sinkOrder:    []string{"pager"},
	})

	// One distinct message per loop. Each is the line NoteTickErr emits for that loop's failing tick, so
	// its presence proves that loop reached the helper WITH this logger.
	want := map[string]string{
		"scheduled correlation (burst rule) failed": "RunCorrelationLoop",
		"beaconing sweep failed":                    "RunBeaconLoop",
		"approval expiry sweep failed":              "RunApprovalExpiryLoop",
		"playbook tick failed":                      "RunPlaybookLoop",
		"itsm sync failed":                          "RunITSMLoop",
		"incident escalation sweep failed":          "RunEscalationLoop",
		"retention purge FAILED":                    "the retention sweep (retain.Loop)",
	}

	deadline := time.Now().Add(30 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		out = sink.String()
		missing := false
		for msg := range want {
			if !strings.Contains(out, msg) {
				missing = true
				break
			}
		}
		if !missing {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// THE EIGHTH LOGGER SITE. startLeaderLoops hands `log` to seven loops and to one more place the
	// loops above cannot reach: the retention sweep's `record` half. Against this dead pool no purge ever
	// SUCCEEDS, and `record` only runs after a successful purge — so reverting that argument to `nil`
	// used to pass this test. Driving the callback directly closes it.
	recordCB, _ := retentionCallbacks(ctx, srv, log)
	recordCB(ctx, "fleet_telemetry", 0, time.Now(), "OPENSHIELD_FLEET_RETENTION=1h")

	cancel()

	// JOIN, as far as loops started with `go` inside startLeaderLoops allow. Their goroutines are not
	// exposed, so the observable equivalent is QUIESCENCE: every one of them ticks at 10ms and fails
	// loudly, so if any were still running the sink would keep growing. A test that merely cancelled
	// would let seven loops run on against a pool it is about to close — the exact discipline startLoop
	// exists to preach, applied to the goroutines this seam does not hand back.
	quiet := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		n := len(sink.String())
		time.Sleep(250 * time.Millisecond)
		if len(sink.String()) == n {
			quiet = true
			break
		}
	}
	if !quiet {
		t.Error("the leader loops were still logging 10s after their context was cancelled — at least " +
			"one did not stop, and it is about to run against a closed pool")
	}

	out = sink.String()
	if !strings.Contains(out, "recording retention event failed") {
		t.Error("the retention sweep's record callback was built WITHOUT the logger this binary " +
			"constructed — srv.RecordRetentionEvent's failures reach no sink. It is the eighth site " +
			"`log` must be threaded to, and the only one no running loop can exercise here.")
	}
	for msg, loop := range want {
		if !strings.Contains(out, msg) {
			t.Errorf("%s was started WITHOUT the logger this binary built — nothing it logged reached "+
				"the sink (expected a line containing %q). A nil at that call site compiles and is "+
				"exactly how the logging half of the stop rule shipped as a no-op.", loop, msg)
		}
	}
	// The stamp travels with the line, or a reader cannot tell an exempted tick from a counted one.
	if !strings.Contains(out, "stopping=false") {
		t.Errorf("no line carried a stopping stamp; got:\n%s", out)
	}
}

// TestRetentionSweepStopIsNotAFailure — the SEVENTH loop's behavioural assertion, and the only one that
// could not live in internal/controlplane because the loop itself lives here.
//
// It is the loop that motivated exporting NoteTickErr at all, and until now it was covered only
// LEXICALLY (loop_guard_test.go proves no counter is incremented inside its literal — it does not prove
// the replacement behaves). It moves TWO counters, and the second is the one no lexical rule can see:
//
//   - RetentionPurgeFailures, from the sweep's own onFailure callback;
//   - RetentionRecordFailures, from srv.RecordRetentionEvent — a method CALLED FROM the loop literal, so
//     the guard is structurally blind to it. On a stop mid-sweep its INSERT fails with context.Canceled
//     and openshield_retention_record_failures_total moved for a routine restart.
//
// Mutation A: drop the `!stopping` condition in NoteTickErr → both counter assertions FAIL.
// Mutation B: make the helper's log conditional on `!stopping` → both line assertions FAIL.
func TestRetentionSweepStopIsNotAFailure(t *testing.T) {
	pool, err := pgxpool.New(context.Background(),
		"postgres://nobody:nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	srv := controlplane.New(pool)

	sink := &wiringSink{}
	log := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelError}))

	// The loop's own context, already cancelled: this is precisely a demotion or a shutdown landing
	// mid-sweep. The callbacks close over it, which is what the exemption is keyed on.
	loopCtx, cancel := context.WithCancel(context.Background())
	cancel()
	record, onFailure := retentionCallbacks(loopCtx, srv, log)

	beforePurge := srv.RetentionPurgeFailures.Load()
	beforeRecord := srv.RetentionRecordFailures.Load()

	runRetentionSweep(loopCtx, []retentionJob{
		// One purge aborted by the stop...
		{target: "fleet_telemetry", unit: "rows", policy: "OPENSHIELD_FLEET_RETENTION=1h",
			cutoff: time.Now().Add(-time.Hour),
			run: func(context.Context, time.Time) (int64, error) { return 0, context.Canceled }},
		// ...and one that SUCCEEDED before the stop, so the record path is genuinely reached. Without
		// this job RecordRetentionEvent never runs and the second half of the test is vacuous.
		{target: "notify_dedupe", unit: "ids", policy: "OPENSHIELD_NOTIFY_DEDUPE_RETENTION=24h",
			cutoff: time.Now().Add(-24 * time.Hour),
			run:    func(context.Context, time.Time) (int64, error) { return 3, nil }},
	}, record, onFailure)

	if got := srv.RetentionPurgeFailures.Load(); got != beforePurge {
		t.Errorf("a stop mid-sweep counted %d retention purge failure(s) — /health names this counter, "+
			"and a clean restart is not data being retained past its window", got-beforePurge)
	}
	if got := srv.RetentionRecordFailures.Load(); got != beforeRecord {
		t.Errorf("a stop mid-sweep counted %d retention RECORD failure(s) — this is the counter reached "+
			"through a method call, which the lexical guard cannot see at all", got-beforeRecord)
	}

	out := sink.String()
	for _, want := range []string{
		"retention purge FAILED",
		"recording retention event failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the exempted sweep left no line matching %q — not counting is about not paging; "+
				"an abandoned purge that leaves nothing behind cannot be explained afterwards", want)
		}
	}
	if !strings.Contains(out, "stopping=true") {
		t.Errorf("no line was stamped as a stop; got:\n%s", out)
	}
}
