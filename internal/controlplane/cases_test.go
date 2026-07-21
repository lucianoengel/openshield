package controlplane_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// F3: the case lifecycle, and the four-eyes control on closure (D36) — a single operator
// cannot both request and approve a close.
func TestCaseFourEyesClosure(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	alice := "operator:alice"
	bob := "operator:bob"

	id, err := srv.OpenCase(ctx, "sub_target", alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.AssignCase(ctx, id, bob); err != nil {
		t.Fatal(err)
	}
	if err := srv.AddNote(ctx, id, alice, "reviewing the burst incident"); err != nil {
		t.Fatal(err)
	}

	// Alice requests closure.
	if err := srv.RequestClose(ctx, id, alice); err != nil {
		t.Fatal(err)
	}

	// Alice CANNOT approve her own closure — four-eyes refuses it, and the case stays open.
	if err := srv.ApproveClose(ctx, id, alice); !errors.Is(err, controlplane.ErrFourEyes) {
		t.Fatalf("self-approval err = %v, want ErrFourEyes", err)
	}
	c, _ := srv.GetCase(ctx, id)
	if c.Status == "closed" {
		t.Fatal("case was closed by a single operator — four-eyes was bypassed")
	}

	// Bob (a different operator) approves — the case closes, recording BOTH parties.
	if err := srv.ApproveClose(ctx, id, bob); err != nil {
		t.Fatalf("second-operator approval failed: %v", err)
	}
	c, _ = srv.GetCase(ctx, id)
	if c.Status != "closed" {
		t.Errorf("status = %q, want closed", c.Status)
	}
	if c.CloseRequestedBy != alice || c.ClosedBy != bob {
		t.Errorf("closure attribution = requested %q / closed %q, want alice/bob", c.CloseRequestedBy, c.ClosedBy)
	}
	if c.ClosedAt == nil {
		t.Error("closed_at not set")
	}
}

// ApproveClose is refused when there is no pending closure request (you cannot close a
// case that no one asked to close).
func TestApproveWithoutRequest(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	id, err := srv.OpenCase(ctx, "sub_x", "operator:alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ApproveClose(ctx, id, "operator:bob"); err == nil {
		t.Error("approved a closure that was never requested")
	}
}
