package controlplane_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// TestMatchesSequence pins the ORDERED-subsequence semantics — the claim the rule actually makes.
//
// Mutation: implement it as set containment ("all these domains fired") → the reversed and
// missing-step cases wrongly match → this FAILS. That mutation matters because set containment is the
// easy implementation and a materially weaker claim: an attack narrative is an ordering claim.
func TestMatchesSequence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ordered []string
		want    []string
		match   bool
	}{
		{"exact", []string{"ueba", "hips", "nips"}, []string{"ueba", "hips", "nips"}, true},
		{"interleaved is still ordered", []string{"ueba", "dlp", "hips", "dlp", "nips"}, []string{"ueba", "hips", "nips"}, true},
		{"reversed does NOT match", []string{"nips", "hips", "ueba"}, []string{"ueba", "hips", "nips"}, false},
		{"partly out of order does NOT match", []string{"ueba", "nips", "hips"}, []string{"ueba", "hips", "nips"}, false},
		{"missing step does NOT match", []string{"ueba", "nips"}, []string{"ueba", "hips", "nips"}, false},
		{"prefix only does NOT match", []string{"ueba", "hips"}, []string{"ueba", "hips", "nips"}, false},
		{"repeats satisfy successive steps", []string{"hips", "hips", "nips"}, []string{"hips", "hips", "nips"}, true},
		{"a single repeat does not satisfy two steps", []string{"hips", "nips"}, []string{"hips", "hips"}, false},
		{"empty want matches anything", []string{"dlp"}, nil, true},
		{"empty want matches an empty list", nil, nil, true},
		{"nothing matches against an empty list", nil, []string{"hips"}, false},
	} {
		if got := controlplane.MatchesSequence(tc.ordered, tc.want); got != tc.match {
			t.Errorf("%s: MatchesSequence(%v, %v) = %v, want %v", tc.name, tc.ordered, tc.want, got, tc.match)
		}
	}
}

// TestEscalateSeverity: one bucket per domain beyond the first, capped at critical, always inside the
// existing four-bucket vocabulary (ADR-10) — never an invented label.
func TestEscalateSeverity(t *testing.T) {
	valid := map[string]bool{
		controlplane.SeverityLow: true, controlplane.SeverityMedium: true,
		controlplane.SeverityHigh: true, controlplane.SeverityCritical: true,
	}
	for _, tc := range []struct {
		base    string
		domains int
		want    string
	}{
		{controlplane.SeverityLow, 1, controlplane.SeverityLow},
		{controlplane.SeverityLow, 2, controlplane.SeverityMedium},
		{controlplane.SeverityLow, 3, controlplane.SeverityHigh},
		{controlplane.SeverityLow, 4, controlplane.SeverityCritical},
		{controlplane.SeverityLow, 9, controlplane.SeverityCritical}, // the cap holds
		{controlplane.SeverityMedium, 2, controlplane.SeverityHigh},
		{controlplane.SeverityHigh, 2, controlplane.SeverityCritical},
		{controlplane.SeverityCritical, 4, controlplane.SeverityCritical},
		{controlplane.SeverityHigh, 1, controlplane.SeverityHigh}, // one domain never escalates
	} {
		got := controlplane.EscalateSeverity(tc.base, tc.domains)
		if got != tc.want {
			t.Errorf("EscalateSeverity(%q, %d) = %q, want %q", tc.base, tc.domains, got, tc.want)
		}
		if !valid[got] {
			t.Errorf("EscalateSeverity(%q, %d) = %q, outside the four-bucket vocabulary", tc.base, tc.domains, got)
		}
	}
	// An unrecognized bucket is never trusted to outrank a known one: it starts at the bottom.
	if got := controlplane.EscalateSeverity("catastrophic", 1); got != controlplane.SeverityLow {
		t.Errorf("EscalateSeverity of an unknown bucket = %q, want %q", got, controlplane.SeverityLow)
	}
}

// TestMaxSeverity: the highest bucket present, and `low` — never an invented value — when there is
// nothing recognizable to report.
func TestMaxSeverity(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"low", "high", "medium"}, controlplane.SeverityHigh},
		{[]string{"low"}, controlplane.SeverityLow},
		{[]string{"critical", "high"}, controlplane.SeverityCritical},
		{[]string{"bogus"}, controlplane.SeverityLow},
		{nil, controlplane.SeverityLow},
		{[]string{"bogus", "medium"}, controlplane.SeverityMedium},
	} {
		if got := controlplane.MaxSeverity(tc.in); got != tc.want {
			t.Errorf("MaxSeverity(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDistinctInOrder: the incident's domain list is deduplicated but keeps first-seen order, so the
// list reads as the sequence the operator saw and is stable to assert against.
func TestDistinctInOrder(t *testing.T) {
	got := controlplane.DistinctInOrder([]string{"ueba", "hips", "ueba", "", "nips", "hips"})
	if strings.Join(got, ",") != "ueba,hips,nips" {
		t.Fatalf("DistinctInOrder = %v, want [ueba hips nips]", got)
	}
	if n := len(controlplane.DistinctInOrder(nil)); n != 0 {
		t.Fatalf("DistinctInOrder(nil) returned %d values, want 0", n)
	}
}
