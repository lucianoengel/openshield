package core

import (
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
