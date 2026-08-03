package core

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ExclusionSet is a first-class privacy primitive (D20): a set of subjects the
// system must NOT observe at all. Exclusion is at the SOURCE — an excluded
// subject produces no event, so no personal data about it is ever created. The
// honest way not to surveil something is not to look at it; redaction after the
// fact still means the content was read and existed in memory.
//
// The operator owns the exclusion set, not the user, so it is a privacy control
// and not a user-invokable way to evade DLP.
type ExclusionSet struct {
	// PathPrefixes: a subject whose path is under one of these is excluded
	// (personal folders, e.g. ~/Private).
	PathPrefixes []string
	// TimeWindows: wall-clock windows during which observation is excluded
	// (break time, off-hours agreed with a works council).
	TimeWindows []TimeWindow
}

// TimeWindow is a daily [Start, End) local-time window, in minutes since
// midnight, e.g. 720..780 for a 12:00–13:00 lunch break.
type TimeWindow struct {
	StartMin int
	EndMin   int
}

func (w TimeWindow) contains(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	return m >= w.StartMin && m < w.EndMin
}

// Excluded reports whether a subject at the given path and time must not be
// observed. Either a path match or a time-window match excludes it.
func (s ExclusionSet) Excluded(path string, at time.Time) bool {
	for _, p := range s.PathPrefixes {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	for _, w := range s.TimeWindows {
		if w.contains(at) {
			return true
		}
	}
	return false
}

// ErrBadTimeWindow is a malformed or unusable exclusion window.
var ErrBadTimeWindow = errors.New("core: invalid exclusion time window")

// ParseTimeWindows parses a comma-separated list of `HH:MM-HH:MM` local-time windows.
//
// REFUSED, never skipped. A silently-dropped window is a control the operator believes is on: they
// wrote a lunch break into the configuration, told a works council about it, and the agent observed
// straight through it. There is no partial success here — the caller starts with no exclusions and
// says why, rather than with some of them.
//
// A window that crosses midnight (23:00-02:00) is refused with its own message rather than split
// automatically. TimeWindow.contains is a half-open [start, end) comparison on minutes since
// midnight, so a crossing window matches NOTHING — the silent-failure shape again. Splitting it into
// two windows is a decision the operator should make explicitly.
func ParseTimeWindows(s string) ([]TimeWindow, error) {
	var out []TimeWindow
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		start, end, ok := strings.Cut(part, "-")
		if !ok {
			return nil, fmt.Errorf("%w: %q is not HH:MM-HH:MM", ErrBadTimeWindow, part)
		}
		sm, err := parseHHMM(strings.TrimSpace(start))
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrBadTimeWindow, part, err)
		}
		em, err := parseHHMM(strings.TrimSpace(end))
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrBadTimeWindow, part, err)
		}
		if em == sm {
			return nil, fmt.Errorf("%w: %q is empty — [start, end) excludes nothing when they are equal",
				ErrBadTimeWindow, part)
		}
		if em < sm {
			return nil, fmt.Errorf("%w: %q ends before it starts; a window crossing midnight matches "+
				"nothing and must be written as two windows", ErrBadTimeWindow, part)
		}
		out = append(out, TimeWindow{StartMin: sm, EndMin: em})
	}
	return out, nil
}

// parseHHMM returns minutes since midnight. It refuses anything that is not exactly HH:MM in range,
// including the shapes time.Parse would accept and quietly reinterpret.
func parseHHMM(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	hh, herr := strconv.Atoi(h)
	mm, merr := strconv.Atoi(m)
	if herr != nil || merr != nil {
		return 0, fmt.Errorf("%q is not numeric", s)
	}
	if hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("%q is out of range", s)
	}
	return hh*60 + mm, nil
}
