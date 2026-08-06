package controlplane_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// View records a labelled view and returns the telemetry; Views reads it back —
// obtaining evidence and leaving a record are one operation (D20).
func TestViewRecordsAndServes(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	// Seed some telemetry for the event directly.
	if _, err := pool.Exec(ctx,
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload) VALUES ('a','event','ev-1','\x00')`); err != nil {
		t.Fatal(err)
	}

	rows, err := srv.View(ctx, "unauthenticated:alice", "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("View returned %d telemetry rows, want 1", len(rows))
	}
	views, err := srv.Views(ctx, "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("Views = %d, want 1 — the view was not recorded", len(views))
	}
	if views[0].Viewer != "unauthenticated:alice" || views[0].EventID != "ev-1" {
		t.Errorf("view record = %+v, want viewer unauthenticated:alice, event ev-1", views[0])
	}
	byViewer, _ := srv.ViewsBy(ctx, "unauthenticated:alice")
	if len(byViewer) != 1 {
		t.Errorf("ViewsBy = %d, want 1", len(byViewer))
	}
}

// An empty viewer is rejected — no unattributable view is silently recorded.
func TestEmptyViewerRejected(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	if _, err := srv.View(ctx, "", "ev-x"); !errors.Is(err, controlplane.ErrNoViewer) {
		t.Errorf("View with empty viewer err = %v, want ErrNoViewer", err)
	}
	if err := srv.RecordView(ctx, controlplane.ViewRecord{
		EventID: "ev-x", Route: "/view",
	}); !errors.Is(err, controlplane.ErrNoViewer) {
		t.Errorf("RecordView with empty viewer err = %v, want ErrNoViewer", err)
	}
	// AND AN EMPTY ROUTE IS REFUSED THE SAME WAY (D483). Migration 053 declares route='' to mean
	// "recorded before CONSOLE-5, no route captured", so a live handler writing '' makes its reads
	// indistinguishable from history and `WHERE route='/cases'` answers nothing forever. That is what
	// all five in-handler recorders did for the whole of D482.
	//
	// Mutation: delete the ErrNoRoute branch from recordViewDetail → this FAILS.
	if err := srv.RecordView(ctx, controlplane.ViewRecord{
		Viewer: "unauthenticated:alice", EventID: "ev-x",
	}); !errors.Is(err, controlplane.ErrNoRoute) {
		t.Errorf("RecordView with no route err = %v, want ErrNoRoute — a routeless row from a live "+
			"handler is one a reader cannot tell from a pre-CONSOLE-5 record", err)
	}
	// Nothing was recorded — by EITHER refusal. Without this the two cases above are satisfied by a
	// function that returns the right error and writes the row anyway.
	views, _ := srv.Views(ctx, "ev-x")
	if len(views) != 0 {
		t.Errorf("a refused view was recorded: %v", views)
	}
}

// The recorded viewer carries the unauthenticated label (callers prefix it).
func TestViewerLabelled(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	if err := srv.RecordView(ctx, controlplane.ViewRecord{
		Viewer: "unauthenticated:bob", SubjectFilter: "subject:s1", Route: "/cases",
	}); err != nil {
		t.Fatal(err)
	}
	views, _ := srv.ViewsBy(ctx, "unauthenticated:bob")
	if len(views) != 1 || !strings.HasPrefix(views[0].Viewer, "unauthenticated:") {
		t.Errorf("viewer not labelled unauthenticated: %+v", views)
	}
}
