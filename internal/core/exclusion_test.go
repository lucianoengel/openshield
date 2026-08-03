package core_test

import (
	"errors"
	"strings"
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

// PRIV-1: exclusion windows are validated where they are read, and a bad one is REFUSED.
//
// Refused, never skipped: a silently-dropped window is a control the operator believes is on. They
// wrote a lunch break into the configuration, told a works council about it, and the agent observed
// straight through it — and there is nothing anywhere that would say so.
//
// Mutation: turn any single rejection below into a skip → that case parses to zero windows and the
// subtest FAILS.
func TestAMalformedExclusionWindowIsRefusedNotSkipped(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []core.TimeWindow
		wantErr bool
	}{
		{"a lunch break", "12:00-13:00", []core.TimeWindow{{StartMin: 720, EndMin: 780}}, false},
		{"two windows", "12:00-13:00, 18:30-19:00",
			[]core.TimeWindow{{StartMin: 720, EndMin: 780}, {StartMin: 1110, EndMin: 1140}}, false},
		{"empty means none", "", nil, false},
		{"whitespace only", "  ,  ", nil, false},
		{"midnight to end of day", "00:00-23:59",
			[]core.TimeWindow{{StartMin: 0, EndMin: 1439}}, false},

		{"no dash", "12:00", nil, true},
		{"not a time", "noon-1pm", nil, true},
		{"single-digit hour", "9:00-10:00", nil, true},
		{"hour out of range", "24:00-25:00", nil, true},
		{"minute out of range", "12:60-13:00", nil, true},
		{"negative", "-1:00-13:00", nil, true},
		// An empty window excludes nothing — [start, end) with start == end is never true — so
		// accepting it would install a control that does nothing.
		{"start equals end", "12:00-12:00", nil, true},
		// A crossing window is the silent-failure shape: contains() compares minutes since midnight,
		// so 23:00-02:00 matches NOTHING. Splitting it into two is the operator's call to make.
		{"crosses midnight", "23:00-02:00", nil, true},
		{"one bad window among good ones", "12:00-13:00,23:00-02:00", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := core.ParseTimeWindows(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ParseTimeWindows(%q) = %v, nil; want an error — a silently-dropped "+
						"window is a privacy control the operator believes is on", c.in, got)
				}
				if !errors.Is(err, core.ErrBadTimeWindow) {
					t.Fatalf("err = %v, want ErrBadTimeWindow", err)
				}
				if !strings.Contains(err.Error(), strings.TrimSpace(strings.Split(c.in, ",")[len(strings.Split(c.in, ","))-1])) &&
					!strings.Contains(err.Error(), strings.TrimSpace(c.in)) {
					t.Errorf("error %q does not quote the offending window", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTimeWindows(%q) = %v", c.in, err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("ParseTimeWindows(%q) = %v, want %v", c.in, got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("ParseTimeWindows(%q) = %v, want %v", c.in, got, c.want)
				}
			}
		})
	}
}

// A parsed window means what the operator wrote: it excludes inside and not outside.
func TestAParsedWindowExcludesExactlyItsInterval(t *testing.T) {
	w, err := core.ParseTimeWindows("12:00-13:00")
	if err != nil {
		t.Fatal(err)
	}
	set := core.ExclusionSet{TimeWindows: w}
	at := func(h, m int) time.Time { return time.Date(2026, 8, 3, h, m, 0, 0, time.Local) }
	for _, c := range []struct {
		t    time.Time
		want bool
	}{
		{at(11, 59), false},
		{at(12, 0), true}, // inclusive start
		{at(12, 30), true},
		{at(12, 59), true},
		{at(13, 0), false}, // exclusive end
		{at(13, 1), false},
	} {
		if got := set.Excluded("", c.t); got != c.want {
			t.Errorf("Excluded at %s = %v, want %v", c.t.Format("15:04"), got, c.want)
		}
	}
}
