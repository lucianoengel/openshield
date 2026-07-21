package core_test

import (
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
)

func TestExclusionByPath(t *testing.T) {
	set := core.ExclusionSet{PathPrefixes: []string{"/home/alice/Private"}}
	at := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)

	if !set.Excluded("/home/alice/Private/diary.txt", at) {
		t.Error("a path under an excluded prefix was not excluded")
	}
	if set.Excluded("/home/alice/Work/report.docx", at) {
		t.Error("a path outside the excluded prefix was wrongly excluded")
	}
	// An empty prefix must not match everything — that would exclude the world.
	empty := core.ExclusionSet{PathPrefixes: []string{""}}
	if empty.Excluded("/anything", at) {
		t.Error("an empty prefix excluded everything")
	}
}

func TestExclusionByTimeWindow(t *testing.T) {
	// 12:00–13:00 break.
	set := core.ExclusionSet{TimeWindows: []core.TimeWindow{{StartMin: 720, EndMin: 780}}}
	lunch := time.Date(2026, 7, 21, 12, 30, 0, 0, time.UTC)
	work := time.Date(2026, 7, 21, 9, 0, 0, 0, time.UTC)

	if !set.Excluded("/home/alice/Work/x", lunch) {
		t.Error("break-time observation was not excluded")
	}
	if set.Excluded("/home/alice/Work/x", work) {
		t.Error("work-time observation was wrongly excluded")
	}
	// The window is half-open: 13:00 exactly is back to work.
	if set.Excluded("/x", time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC)) {
		t.Error("the window end must be exclusive")
	}
}

func TestRetentionExpiryAndHold(t *testing.T) {
	now := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	old := now.Add(-400 * 24 * time.Hour)
	recent := now.Add(-10 * 24 * time.Hour)

	if !core.RetentionStandard.Expired(old, now) {
		t.Error("a 400-day-old standard entry should be expired (365d)")
	}
	if core.RetentionStandard.Expired(recent, now) {
		t.Error("a 10-day-old standard entry should not be expired")
	}
	// Investigation is HELD — never expires, however old.
	ancient := now.Add(-100 * 365 * 24 * time.Hour)
	if core.RetentionInvestigation.Expired(ancient, now) {
		t.Error("an investigation-class entry must never expire under routine retention")
	}
	// Unspecified must NOT be an indefinite-retention hole.
	if !core.RetentionUnspecified.Expired(old, now) {
		t.Error("an unspecified-class entry must be treated as bounded, not kept forever")
	}
}

// A connector consults the exclusion set and produces NO event for an excluded
// subject — exclusion at the source. This models the guard the real fanotify
// connector places at event production: the excluded subject's content is never
// read, so no personal data about it is created.
func TestExcludedSubjectProducesNoEvent(t *testing.T) {
	set := core.ExclusionSet{PathPrefixes: []string{"/home/alice/Private"}}
	at := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)

	// A stand-in producer: returns an event only if the subject is not excluded.
	produce := func(path string) bool {
		if set.Excluded(path, at) {
			return false // no event
		}
		return true
	}
	if produce("/home/alice/Private/secret.txt") {
		t.Error("an excluded path produced an event — exclusion must stop production at the source")
	}
	if !produce("/home/alice/Work/report.docx") {
		t.Error("a non-excluded path failed to produce an event")
	}
}
