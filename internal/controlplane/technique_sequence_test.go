package controlplane

import (
	"reflect"
	"testing"
)

// XDR-4b: the ordered-technique subsequence, tested in Go rather than in SQL — the same split of
// work XDR-4's domain sequence made, for the same reason: the ordering semantics are the subtle part
// and every branch is provable without a database.
func TestATechniqueSequenceIsAnOrderingClaim(t *testing.T) {
	cases := []struct {
		name     string
		perAlert [][]string // the entity's alerts in detection order, each with its techniques
		want     []string
		match    bool
	}{
		{
			name:     "no constraint matches anything",
			perAlert: [][]string{{"T1552"}},
			want:     nil,
			match:    true,
		},
		{
			name:     "consecutive alerts in order",
			perAlert: [][]string{{"T1552"}, {"T1567.002"}},
			want:     []string{"T1552", "T1567.002"},
			match:    true,
		},
		{
			name:     "unrelated techniques in between are allowed",
			perAlert: [][]string{{"T1552"}, {"T1027"}, {"T1059"}, {"T1567.002"}},
			want:     []string{"T1552", "T1567.002"},
			match:    true,
		},
		{
			name:     "an alert with several techniques can satisfy one step",
			perAlert: [][]string{{"T1027", "T1552"}, {"T1567.002"}},
			want:     []string{"T1552", "T1567.002"},
			match:    true,
		},
		{
			// THE RULE THAT IS NOT OBVIOUS. Copying a private key into a cloud-sync folder evidences
			// BOTH techniques from ONE event. Set containment would call that "T1552 then
			// T1567.002". It is not: one alert is one moment, and a moment cannot evidence "then".
			name:     "two steps are NOT satisfied by one alert",
			perAlert: [][]string{{"T1552", "T1567.002"}},
			want:     []string{"T1552", "T1567.002"},
			match:    false,
		},
		{
			// The same reasoning XDR-4 recorded for domains: the reverse order is a different claim.
			name:     "reverse order does not match",
			perAlert: [][]string{{"T1567.002"}, {"T1552"}},
			want:     []string{"T1552", "T1567.002"},
			match:    false,
		},
		{
			name:     "a missing step fails even when the others are present",
			perAlert: [][]string{{"T1552"}, {"T1567.002"}},
			want:     []string{"T1552", "T1218", "T1567.002"},
			match:    false,
		},
		{
			name:     "alerts with no technique are skipped, not treated as wildcards",
			perAlert: [][]string{{"T1552"}, {}, {}, {"T1567.002"}},
			want:     []string{"T1552", "T1567.002"},
			match:    true,
		},
		{
			name:     "no alert carries a technique",
			perAlert: [][]string{{}, {}},
			want:     []string{"T1552"},
			match:    false,
		},
		{
			name:     "a three-step chain across three alerts",
			perAlert: [][]string{{"T1552"}, {"T1218", "T1027"}, {"T1567.002"}},
			want:     []string{"T1552", "T1218", "T1567.002"},
			match:    true,
		},
		{
			// A repeated step needs two distinct alerts — the same rule, applied to itself.
			name:     "a repeated step needs two alerts",
			perAlert: [][]string{{"T1552"}},
			want:     []string{"T1552", "T1552"},
			match:    false,
		},
		{
			name:     "a repeated step across two alerts matches",
			perAlert: [][]string{{"T1552"}, {"T1552"}},
			want:     []string{"T1552", "T1552"},
			match:    true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := matchesTechniqueSequence(c.perAlert, c.want); got != c.match {
				t.Fatalf("matchesTechniqueSequence(%v, %v) = %v, want %v",
					c.perAlert, c.want, got, c.match)
			}
		})
	}
}

// The per-alert aggregation arrives space-joined, because array_agg over a TEXT[] column would build
// a two-dimensional array that Postgres requires to be RECTANGULAR — one alert with two techniques
// and another with one errors at runtime on real data. This is the round trip.
func TestRaggedTechniqueListsSurviveTheJoinedAggregation(t *testing.T) {
	joined := []string{"T1552 T1567.002", "", "T1218", "T1027 T1059 T1071"}
	want := [][]string{{"T1552", "T1567.002"}, nil, {"T1218"}, {"T1027", "T1059", "T1071"}}
	got := splitTechniques(joined)
	if len(got) != len(want) {
		t.Fatalf("splitTechniques returned %d rows, want %d — one entry per alert, so a dropped "+
			"row would shift every later technique to an earlier alert and change the ordering claim",
			len(got), len(want))
	}
	for i := range want {
		if len(got[i]) == 0 && len(want[i]) == 0 {
			continue
		}
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("alert %d = %v, want %v", i, got[i], want[i])
		}
	}
}
