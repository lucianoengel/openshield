package controlplane_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// TestRequesterCannotApproveTheirOwnRequest is the control itself.
func TestRequesterCannotApproveTheirOwnRequest(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	id, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-1",
		"operator:alice", "contain host A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ResolveApproval(ctx, id, "operator:alice", true); !errors.Is(err, controlplane.ErrFourEyes) {
		t.Fatalf("self-approval err = %v, want ErrFourEyes — one operator must not be able to both request "+
			"and approve a containment", err)
	}
	got, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != controlplane.ApprovalPending {
		t.Fatalf("after a refused self-approval the state is %q, want still pending", got.State)
	}

	// A DIFFERENT operator can.
	if err := srv.ResolveApproval(ctx, id, "operator:bob", true); err != nil {
		t.Fatalf("second-operator approval: %v", err)
	}
	got, _ = srv.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-1")
	if got.State != controlplane.ApprovalApproved || got.Approver != "operator:bob" || got.ResolvedAt == nil {
		t.Fatalf("approved record = %+v, want approved and attributed to bob", got)
	}
}

// TestConcurrentApprovalsProduceExactlyOneOutcome: the reason the comparison lives in the UPDATE predicate.
//
// Mutation: do the still-pending / requester≠approver checks in Go before an unconditional UPDATE → more
// than one approver succeeds for some subject → this FAILS.
//
// It repeats over many subjects DELIBERATELY. A single 8-way race is a probabilistic detector and the first
// version of this test proved it: the pre-check mutant PASSED once, because Postgres round-trip timing
// happened to serialize the readers behind the first writer. Racing many independent subjects makes the
// window overwhelmingly likely to open at least once, which is the difference between a test that catches
// the bug and one that catches it on a good day.
func TestConcurrentApprovalsProduceExactlyOneOutcome(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	const (
		rounds    = 25
		approvers = 8
	)
	for round := 0; round < rounds; round++ {
		subject := "step-" + strconv.Itoa(round)
		id, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectPlaybookStep, subject,
			"operator:alice", "", time.Hour)
		if err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		results := make([]error, approvers)
		start := make(chan struct{})
		for i := 0; i < approvers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i] = srv.ResolveApproval(ctx, id, "operator:approver-"+strconv.Itoa(i), true)
			}(i)
		}
		close(start)
		wg.Wait()

		var succeeded int
		for _, err := range results {
			if err == nil {
				succeeded++
			}
		}
		if succeeded != 1 {
			t.Fatalf("round %d: %d of %d concurrent approvals succeeded, want exactly 1 — the four-eyes "+
				"rule must be atomic, not a check followed by a write", round, succeeded, approvers)
		}
	}
}

// TestExpiredApprovalCannotBeApproved: a request left open is not consent.
//
// Mutation: drop `expires_at > now()` from the predicate → the expired request is approved → this FAILS.
func TestExpiredApprovalCannotBeApproved(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	// A TTL that has already elapsed by the time we resolve.
	id, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-expired",
		"operator:alice", "", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	if err := srv.ResolveApproval(ctx, id, "operator:bob", true); !errors.Is(err, controlplane.ErrApprovalExpired) {
		t.Fatalf("approving an expired request err = %v, want ErrApprovalExpired", err)
	}
	// And a reader sees it as expired even before the (cosmetic) sweeper runs.
	got, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-expired")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != controlplane.ApprovalExpired {
		t.Errorf("a timed-out request reads as %q, want expired — a dead request must never look live", got.State)
	}
	if n, err := srv.ExpirePendingApprovals(ctx); err != nil || n == 0 {
		t.Errorf("the sweeper relabelled %d rows (err %v), want at least 1", n, err)
	}
}

// TestApprovalOutcomeIsTerminal: a decided request cannot be decided again, or the record of who decided it
// would be erasable.
func TestApprovalOutcomeIsTerminal(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	id, _ := srv.RequestApproval(ctx, controlplane.ApprovalSubjectCaseClose, "case-9", "operator:alice", "", time.Hour)
	if err := srv.ResolveApproval(ctx, id, "operator:bob", false); err != nil {
		t.Fatal(err)
	}
	if err := srv.ResolveApproval(ctx, id, "operator:carol", true); !errors.Is(err, controlplane.ErrApprovalNotPending) {
		t.Fatalf("re-resolving err = %v, want ErrApprovalNotPending", err)
	}
	got, _ := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectCaseClose, "case-9")
	if got.State != controlplane.ApprovalDenied || got.Approver != "operator:bob" {
		t.Fatalf("the original outcome was overwritten: %+v", got)
	}
}

// TestApprovalIsBoundToItsSubject: an approval for one action must never satisfy another.
func TestApprovalIsBoundToItsSubject(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	id, _ := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-A",
		"operator:alice", "", time.Hour)
	if err := srv.ResolveApproval(ctx, id, "operator:bob", true); err != nil {
		t.Fatal(err)
	}
	// A different subject id under the same kind has no approval...
	if _, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-B"); !errors.Is(err, controlplane.ErrApprovalNotFound) {
		t.Error("an approval for intent-A was returned for intent-B")
	}
	// ...and neither does the same id under a different kind.
	if _, err := srv.ApprovalFor(ctx, controlplane.ApprovalSubjectPlaybookStep, "intent-A"); !errors.Is(err, controlplane.ErrApprovalNotFound) {
		t.Error("an approval for a response-intent satisfied a playbook-step lookup")
	}
}

// TestOnePendingApprovalPerSubject: two live requests for one action would let a requester shop for an
// approver.
func TestOnePendingApprovalPerSubject(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	if _, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-dup",
		"operator:alice", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-dup",
		"operator:alice", "", time.Hour); err == nil {
		t.Fatal("a second PENDING approval for the same subject was accepted — a requester could open " +
			"several and shop for an approver")
	}
}
