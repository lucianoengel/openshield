package controlplane_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// Hardening (F2→F3): a correlated incident becomes a case in one step, pre-populated with a
// note summarizing the correlated evidence.
func TestOpenCaseForIncident(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	inc := controlplane.Incident{
		SubjectID:  "sub_incident",
		AlertCount: 5,
		MaxRisk:    0.97,
		FirstSeen:  now.Add(-1 * time.Hour),
		LastSeen:   now,
	}
	id, err := srv.OpenCaseForIncident(ctx, inc, "operator:alice")
	if err != nil {
		t.Fatal(err)
	}

	c, err := srv.GetCase(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if c.SubjectID != "sub_incident" || c.OpenedBy != "operator:alice" || c.Status != "open" {
		t.Errorf("case = %+v, want the incident's subject, opened by alice, open", c)
	}

	// The opening note carries the incident summary (count + peak risk), attributed to the
	// correlation system, not a person.
	notes, err := srv.CaseNotes(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 {
		t.Fatalf("notes = %d, want 1 (the auto summary)", len(notes))
	}
	if notes[0].Author != "system:correlation" {
		t.Errorf("note author = %q, want system:correlation", notes[0].Author)
	}
	if !strings.Contains(notes[0].Note, "5 alerts") || !strings.Contains(notes[0].Note, "0.97") {
		t.Errorf("note = %q, want the incident count and peak risk", notes[0].Note)
	}
}

// A subjectless incident does not open a case (nothing to investigate, and the note would
// be meaningless).
func TestOpenCaseForIncidentRejectsEmpty(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	if _, err := srv.OpenCaseForIncident(context.Background(), controlplane.Incident{}, "operator:x"); err == nil {
		t.Error("opened a case for an empty incident")
	}
}
