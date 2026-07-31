package main

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/canary"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// HIPS-8 at the event boundary: an attribution becomes something a POLICY can decide about.
//
// The attribution itself is tested in internal/canary. What is tested here is the shape it takes on the
// wire, which is where it either becomes actionable or stays a log line: the target has to be a PROCESS,
// because a policy that decides to kill decides about one process and wants its own audit row naming it.

func TestASuspectBecomesAProcessTargetedEvent(t *testing.T) {
	att := canary.Attribution{Supported: true, Suspects: []canary.Suspect{
		{PID: 4711, Exe: "/usr/bin/openssl", StartTicks: 998877, OpenPaths: 12},
		{PID: 4712, Exe: "", StartTicks: 0, OpenPaths: 3},
	}}
	evs := suspectEvents("/home/alice/Documents", att)
	if len(evs) != 2 {
		t.Fatalf("got %d events, want one per suspect", len(evs))
	}

	first := evs[0]
	p := first.GetProcess()
	if p == nil {
		t.Fatalf("the event's target is %T, want a ProcessSubject — a directory-targeted event tells a "+
			"policy what happened and not what to act on, and the whole point of attribution is that "+
			"there is now something to act on", first.GetTarget())
	}
	if p.GetPid() != 4711 || p.GetExecPath() != "/usr/bin/openssl" {
		t.Errorf("the suspect's identity did not survive onto the event: %+v", p)
	}
	if p.GetStartTicks() != 998877 {
		t.Errorf("the start time was dropped (%d) — with the pid it identifies the process INSTANCE, "+
			"and a kill decided now without it can land on a recycled pid (HIPS-7)", p.GetStartTicks())
	}
	if first.GetKind() != corev1.EventKind_EVENT_KIND_RANSOMWARE_SUSPECTED {
		t.Errorf("kind = %v, want RANSOMWARE_SUSPECTED", first.GetKind())
	}

	// The ids share the directory event's prefix, so a timeline joins them with no correlation rule.
	dirEvent := canaryEvent("/home/alice/Documents", 0.95)
	if !strings.HasPrefix(first.GetEventId(), dirEvent.GetEventId()) {
		t.Errorf("the suspect event id %q does not extend the detection's %q — an operator reading one "+
			"has no way back to the other", first.GetEventId(), dirEvent.GetEventId())
	}
	if evs[0].GetEventId() == evs[1].GetEventId() {
		t.Error("two suspects share one event id, so the second overwrites the first wherever ids dedupe")
	}

	// A SUSPECT WITH NO EXECUTABLE PATH IS STILL EMITTED. "A process we cannot identify has your
	// documents open" is MORE alarming than a named one, not less, and dropping it would remove exactly
	// the case worth escalating.
	if evs[1].GetProcess().GetPid() != 4712 {
		t.Error("the unnamed suspect was dropped")
	}
}

// An attribution that found nothing produces no events — and the caller reports blindness separately,
// so silence here never has to carry the meaning "nothing was responsible".
func TestNoSuspectsProducesNoEvents(t *testing.T) {
	if evs := suspectEvents("/tmp/x", canary.Attribution{Supported: true}); len(evs) != 0 {
		t.Fatalf("got %d events from an empty attribution", len(evs))
	}
	blind := canary.Attribution{Supported: true, Scanned: 300, Unreadable: 299}
	if evs := suspectEvents("/tmp/x", blind); len(evs) != 0 {
		t.Fatalf("got %d events from a blind attribution", len(evs))
	}
	if !blind.Blind() {
		t.Fatal("the caller cannot tell a blind attribution from a clean one, so its log line would " +
			"report a machine as fine that nobody was able to examine")
	}
}
