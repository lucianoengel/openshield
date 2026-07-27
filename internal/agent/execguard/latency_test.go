package execguard_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/execguard"
	"github.com/lucianoengel/openshield/internal/agent/execipc"
	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/policy"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// THE EXEC PERMISSION WINDOW IS A CORRECTNESS BUDGET, NOT A PERFORMANCE ONE (D301).
//
// When the privileged agent asks the engine whether an exec may proceed, the kernel is holding the
// process. The IPC client gives up after `execipc.DefaultTimeout` and FAILS OPEN — deliberately, because
// a dead engine must never brick execution (D17/D73). That fail-open is what makes latency a correctness
// property rather than a speed one: an engine that answers slowly does not answer LATE, it does not
// answer at all, and **HIPS-3 silently degrades to allow-and-audit while every log line still says
// inline prevention is ACTIVE.**
//
// That is the worst failure shape this project has: a control that reports itself working while
// permitting everything. So this test fails the build when the decision path stops fitting in the window,
// the same way an invariant regression does.
//
// WHAT IT MEASURES is the production path: a real exec-permission event, through the real
// `execguard.Decider`, through a real engine, with the REAL SANDBOXED WORKER as a subprocess. The worker
// round trip is most of the cost and skipping it would measure the wrong thing.

// recLedger is a no-op ledger — persistence is not in the permission window (the audit is written after
// the verdict is returned), so including a database here would measure something the kernel is not
// waiting for.
type recLedger struct{}

func (recLedger) Append(context.Context, *core.Entry) error { return nil }
func (recLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}
func (recLedger) Close() error { return nil }

func TestTheExecDecisionFitsInThePermissionWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("latency budget measured in the full run")
	}
	ctx := context.Background()
	bin := filepath.Join(t.TempDir(), "openshield-worker")
	if out, err := exec.Command("go", "build", "-o", bin, "../../../cmd/openshield-worker").CombinedOutput(); err != nil {
		t.Fatalf("building the worker: %v\n%s", err, out)
	}
	w, err := privileged.StartWorker(ctx, bin)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	pol, err := policy.NewDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.NewFromWorker(w, pol, recLedger{}, nil, 10*time.Second)
	eng.SetSubject("latency-host")
	decide := execguard.Decider(eng)

	// A real executable, because the classifier reads what is at the path. Measuring against a
	// non-existent path would measure the error path, which is fast and not the one under budget.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ev := watchdog.PermissionEvent{PID: int32(os.Getpid()), Path: self}

	// Warm up: the first call pays for OPA's first evaluation and the worker's first round trip, neither
	// of which a running agent pays per exec. Including them would measure startup, not steady state.
	for i := 0; i < 5; i++ {
		if _, err := decide(ctx, ev); err != nil {
			t.Fatalf("warm-up decision failed: %v", err)
		}
	}

	const n = 100
	samples := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if _, err := decide(ctx, ev); err != nil {
			t.Fatalf("decision %d failed: %v", i, err)
		}
		samples = append(samples, time.Since(start))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p50 := samples[len(samples)/2]
	p99 := samples[(len(samples)*99)/100]
	worst := samples[len(samples)-1]
	t.Logf("exec decision latency over %d samples: p50=%s p99=%s max=%s (budget %s)",
		n, p50, p99, worst, execipc.DefaultTimeout)

	// THE BUDGET IS THE IPC CLIENT'S TIMEOUT, not the agent's larger watchdog budget: the client is what
	// gives up first, so it is the deadline that decides whether a verdict is delivered at all.
	//
	// Asserted on p99 rather than the max: a single scheduler hiccup on a shared build machine is not a
	// regression, and a test that fails on one is a test that gets marked flaky and ignored. A p99 over
	// budget means one exec in a hundred fails open, which is a real degradation.
	if p99 > execipc.DefaultTimeout {
		t.Errorf("p99 exec decision latency is %s, over the %s permission window. Every over-budget "+
			"verdict FAILS OPEN, so this does not make the product slow — it makes inline prevention stop "+
			"happening while every log line still reports it as active", p99, execipc.DefaultTimeout)
	}
	// A generous absolute ceiling on the worst case too: a max far past the window means something
	// pathological (a stall, a lock, a GC pause of a kind the D19 spike ruled out), which p99 can hide.
	if worst > 4*execipc.DefaultTimeout {
		t.Errorf("worst-case exec decision latency is %s, far past the %s window — a p99 within budget "+
			"can hide a stall that blocks one exec for most of a second", worst, execipc.DefaultTimeout)
	}
	if _, ok := any(decide).(execguard.ExecDecider); !ok {
		t.Error("Decider no longer returns an ExecDecider")
	}
	_ = corev1.Action_ACTION_ALLOW
}

// TestTheDeciderProducesAValidEvent is the regression guard for the defect the latency test uncovered.
//
// It is separate because the latency test is about a different property and can be skipped in a short
// run — and this one must never be skipped. The engine-backed exec gate had NO provenance on its events
// (`event_id`, `connector_id`), so `core.ValidateEvent` rejected every one, `Process` returned an error,
// and the watchdog fail-opened. Inline prevention denied nothing while the agent reported it ACTIVE.
//
// It asserts against `core.ValidateEvent` — the engine's own gate — rather than checking fields by hand,
// so a future field becoming mandatory fails HERE, at the producer, instead of silently disabling the
// gate again.
func TestTheDeciderProducesAValidEvent(t *testing.T) {
	var captured *corev1.Event
	decide := execguard.Decider(processorFunc(func(_ context.Context, ev *corev1.Event) (*corev1.Decision, error) {
		captured = ev
		return &corev1.Decision{Action: corev1.Action_ACTION_ALLOW}, nil
	}))
	if _, err := decide(context.Background(), watchdog.PermissionEvent{PID: 4242, Path: "/usr/bin/tool"}); err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("the decider ran no event through the processor")
	}
	// The engine stamps subject/agent/timestamp/purpose in attribute(); the PRODUCER owns identity and
	// source. Fill the engine's half here so the assertion isolates the producer's.
	captured.Subject = &corev1.Subject{PseudonymousId: "subject"}
	captured.AgentId = "agent"
	captured.Purpose = corev1.Purpose_PURPOSE_DLP
	captured.ObservedAt = timestamppb.Now()
	if err := core.ValidateEvent(captured); err != nil {
		t.Errorf("the exec event does not satisfy the engine's own validation: %v\n"+
			"    Every exec-permission decision then fails, and the watchdog FAILS OPEN — inline "+
			"prevention stops denying while the agent still reports it active.", err)
	}

	// Ids must be UNIQUE. Pids are reused, so a pid-only id would collapse two execs into one wherever
	// events are keyed by it.
	first := captured.GetEventId()
	if _, err := decide(context.Background(), watchdog.PermissionEvent{PID: 4242, Path: "/usr/bin/tool"}); err != nil {
		t.Fatal(err)
	}
	if captured.GetEventId() == first {
		t.Errorf("two execs of the same pid produced the same event id %q", first)
	}
}

type processorFunc func(context.Context, *corev1.Event) (*corev1.Decision, error)

func (f processorFunc) Process(ctx context.Context, ev *corev1.Event) (*corev1.Decision, error) {
	return f(ctx, ev)
}
