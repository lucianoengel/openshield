package prefilter_test

import (
	"context"
	"crypto/ed25519"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/openipc"
	"github.com/lucianoengel/openshield/internal/agent/prefilter"
	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/policy"
)

// THE FILE-OPEN PERMISSION WINDOW IS A CORRECTNESS BUDGET, NOT A PERFORMANCE ONE (B2/D352).
//
// When the privileged gate asks the engine whether an open may proceed, the kernel is holding the
// opening process — uninterruptibly. The IPC client gives up after `openipc.DefaultTimeout` and FAILS
// OPEN, deliberately, because a gate that failed closed would hang every process on the host.
//
// That fail-open is what makes latency a CORRECTNESS property here. An engine that answers slowly does
// not answer late; it does not answer at all, and the gate silently degrades to allow-and-audit while
// every log line still reports inline prevention as active. Same failure shape D301 measured for the
// exec gate, and the reason that test exists.
//
// THIS ONE IS THE HARDER CASE. An exec decision classifies a path; an open decision classifies a
// BOUNDED PREFIX — up to openipc.MaxPrefixLen of real bytes, moved across a socket and parsed in the
// worker. That is the cost that decides whether this gate is deployable on a directory anyone actually
// uses, and it is measured at the CEILING rather than at a convenient size, because the ceiling is what
// an operator gets by default.

type nopLedger struct{}

func (nopLedger) Append(context.Context, *core.Entry) error { return nil }
func (nopLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}
func (nopLedger) Close() error { return nil }

// TestTheOpenDecisionFitsThePermissionWindow measures the production path: a real sandboxed worker
// subprocess, the real default policy, and a full-size prefix.
func TestTheOpenDecisionFitsThePermissionWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement; skipped under -short")
	}
	if raceDetectorOn {
		// A LATENCY MEASUREMENT UNDER THE RACE DETECTOR MEASURES THE RACE DETECTOR. It instruments every
		// memory access, costing several times the real work, so the number would be neither the
		// production cost nor a stable threshold — and a build gate that fails on instrumentation
		// overhead is one that gets marked flaky and ignored.
		//
		// It skips rather than loosening its budget, because a budget wide enough to pass under
		// instrumentation would no longer fail when the real path regressed, which is the only thing
		// this test is for.
		t.Skip("latency measurement is meaningless under -race; run without it")
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
	// The deadline the engine side actually uses when serving the gate.
	dec := prefilter.NewDecider(w, pol, uint64(openipc.MaxPrefixLen), 120*time.Millisecond, nil)

	// A FULL-SIZE prefix of realistic content: text with structure the detectors will actually walk,
	// not a block of zeroes that every scanner short-circuits on. Measuring against incompressible
	// nonsense would measure the fast path and call it the budget.
	line := []byte("2026-07-28T10:00:00Z name=alice dept=finance note=quarterly reconciliation\n")
	prefix := make([]byte, 0, openipc.MaxPrefixLen)
	for len(prefix) < openipc.MaxPrefixLen {
		prefix = append(prefix, line...)
	}
	prefix = prefix[:openipc.MaxPrefixLen]

	// Warm up: the first calls pay for OPA's first evaluation and the worker's first round trip, neither
	// of which a running gate pays per open.
	for i := 0; i < 5; i++ {
		if _, err := dec.DecideBytes(ctx, "/watched/file.txt", prefix); err != nil {
			t.Fatalf("warm-up decision failed: %v", err)
		}
	}

	const n = 100
	samples := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if _, err := dec.DecideBytes(ctx, "/watched/file.txt", prefix); err != nil {
			t.Fatalf("decision %d failed: %v", i, err)
		}
		samples = append(samples, time.Since(start))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p50 := samples[len(samples)/2]
	p99 := samples[(len(samples)*99)/100]
	worst := samples[len(samples)-1]
	t.Logf("open decision latency over %d samples at a %dKiB prefix: p50=%s p99=%s max=%s (budget %s)",
		n, openipc.MaxPrefixLen>>10, p50, p99, worst, openipc.DefaultTimeout)

	// THE BUDGET IS THE IPC CLIENT'S TIMEOUT, not the watchdog's larger one: the client gives up first,
	// so it is what decides whether a verdict is delivered at all.
	//
	// p99 rather than max: one scheduler hiccup on a shared machine is not a regression, and a test that
	// fails on one gets marked flaky and ignored. A p99 over budget means one open in a hundred fails
	// open — real degradation of a control that still reports itself active.
	if p99 > openipc.DefaultTimeout {
		t.Errorf("p99 open decision latency is %s, over the %s window. Every over-budget verdict FAILS "+
			"OPEN, so this does not make the product slow — it makes the file-open gate stop happening "+
			"while every log line still reports it as active", p99, openipc.DefaultTimeout)
	}
	// A generous absolute ceiling too: a max far past the window means something pathological that p99
	// can hide.
	if worst > 4*openipc.DefaultTimeout {
		t.Errorf("worst-case open decision latency is %s, far past the %s window — a stall rather than "+
			"a slow path", worst, openipc.DefaultTimeout)
	}

	// THE COST SCALES WITH THE PREFIX, and an operator needs the curve rather than one number. Fitting
	// the budget is not the same as being deployable: at the ceiling this costs tens of milliseconds per
	// open, which is fine for a directory of sensitive documents and ruinous for a source tree. The knob
	// that makes it usable on a busier directory is the prefix size, so measure what it buys.
	for _, size := range []int{4 << 10, 16 << 10, openipc.MaxPrefixLen} {
		d := prefilter.NewDecider(w, pol, uint64(size), 120*time.Millisecond, nil)
		body := prefix[:size]
		for i := 0; i < 3; i++ {
			if _, err := d.DecideBytes(ctx, "/watched/file.txt", body); err != nil {
				t.Fatal(err)
			}
		}
		s := make([]time.Duration, 0, 30)
		for i := 0; i < 30; i++ {
			start := time.Now()
			if _, err := d.DecideBytes(ctx, "/watched/file.txt", body); err != nil {
				t.Fatal(err)
			}
			s = append(s, time.Since(start))
		}
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		t.Logf("  prefix %5dKiB: p50=%-12s p99=%s", size>>10, s[len(s)/2], s[(len(s)*99)/100])
	}
}
