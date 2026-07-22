package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// HON-2: opening a case places an ACTIVE legal hold on the subject's evidence, so a purge
// cannot erase it while the investigation is open; closing (releasing) ends the hold.
func TestOpenCasePlacesLegalHold(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	// A subject with no case is NOT under hold.
	if held, err := srv.IsUnderLegalHold(ctx, "sub_free"); err != nil || held {
		t.Fatalf("sub_free under hold = %v (err %v), want false", held, err)
	}

	// Opening a case holds the subject.
	if _, err := srv.OpenCase(ctx, "sub_held", "operator:alice"); err != nil {
		t.Fatal(err)
	}
	held, err := srv.IsUnderLegalHold(ctx, "sub_held")
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Error("opening a case did not place a legal hold on the subject (HON-2)")
	}

	// Releasing ends the hold.
	if err := srv.ReleaseLegalHold(ctx, "sub_held"); err != nil {
		t.Fatal(err)
	}
	if held, _ := srv.IsUnderLegalHold(ctx, "sub_held"); held {
		t.Error("the hold survived release")
	}
}

// Opening a case from an incident also holds the subject (the F2→F3 path).
func TestOpenCaseForIncidentPlacesLegalHold(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	inc := controlplane.Incident{SubjectID: "sub_inc", AlertCount: 3, MaxRisk: 0.9, FirstSeen: time.Now().Add(-time.Hour), LastSeen: time.Now()}
	if _, err := srv.OpenCaseForIncident(ctx, inc, "operator:bob"); err != nil {
		t.Fatal(err)
	}
	if held, _ := srv.IsUnderLegalHold(ctx, "sub_inc"); !held {
		t.Error("opening a case from an incident did not place a legal hold")
	}
}

// Two cases on the same subject do not error (the hold is idempotent).
func TestLegalHoldIdempotent(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	if _, err := srv.OpenCase(ctx, "sub_dup", "operator:a"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.OpenCase(ctx, "sub_dup", "operator:b"); err != nil {
		t.Fatalf("second case on the same subject errored (hold not idempotent): %v", err)
	}
}
