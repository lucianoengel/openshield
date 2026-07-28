package prefilter_test

import (
	"context"
	"crypto/ed25519"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/prefilter"
	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/policy"
)

// A GATED DECISION MUST BECOME EVIDENCE (B2).
//
// The decider used to record nothing, on the stated grounds that "the async engine owns the durable
// audit row". For the inline file-open gate there is no async engine downstream — those events reach
// no pipeline — so a gated open, including a DENIED one, produced NO LEDGER ROW AT ALL.
//
// That is the gap, not the audit: for a platform whose thesis is that every decision is explainable,
// reproducible and cryptographically auditable, an inline refusal that leaves no trace is the one
// decision nobody can review.

// capturingLedger records what it was appended.
type capturingLedger struct {
	mu      sync.Mutex
	entries []*core.Entry
}

func (l *capturingLedger) Append(_ context.Context, e *core.Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	return nil
}
func (l *capturingLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}
func (l *capturingLedger) Close() error { return nil }
func (l *capturingLedger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func TestAGatedDecisionIsRecorded(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a worker subprocess")
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

	led := &capturingLedger{}
	sink := core.NewAuditSink(led)
	d := prefilter.NewDecider(w, pol, 16<<10, 5*time.Second, nil)

	// The outcome is handed over INSIDE the window, so the sink here mimics production: it hands off
	// and the append happens after. Recording synchronously would hold a blocked process for the
	// duration of a database write.
	type item struct {
		st *core.State
		o  core.Outcome
	}
	q := make(chan item, 8)
	d.SetOnOutcome(func(_ context.Context, st *core.State, o core.Outcome) error {
		q <- item{st, o}
		return nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for it := range q {
			_ = sink.Record(ctx, it.st, it.o)
		}
	}()

	// A checksum-backed CPF, so the decision is a real detection rather than an empty allow — a ledger
	// row for a decision about nothing would not show that the content path ran.
	if _, err := d.DecideBytes(ctx, "/watched/report.csv", []byte("name,cpf\nalice,111.444.777-35\n")); err != nil {
		t.Fatal(err)
	}
	close(q)
	<-done

	if led.count() == 0 {
		t.Fatal("a gated decision produced NO ledger entry. The gate refuses opens and leaves no " +
			"evidence, so the one decision an investigator most wants to review is the one that was " +
			"never written")
	}
	e := led.entries[0]
	if e.Decision.GetAction() == 0 {
		t.Errorf("the recorded entry carries no action: %+v", e.Decision)
	}
	// AND IT IS CONTENT-FREE. The prefix is attacker-controlled file content, and the ledger is the
	// most copied artefact in the system (D10/D29).
	if e.Decision.GetReason() != "" && contains(e.Decision.GetReason(), "111.444.777-35") {
		t.Errorf("the ledger entry contains the value that triggered it: %q", e.Decision.GetReason())
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
