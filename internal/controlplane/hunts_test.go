package controlplane_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// A hunt file is validated at LOAD against the real domain and technique vocabularies (XDR-4c).
//
// The interactive path already refuses these inputs with a 400. The file path is the same input
// arriving through a different door, and the failure there is worse: an ad-hoc query returns
// immediately, while a mistyped hunt sits in the deployed file matching nothing for as long as it is
// configured — and nothing-matched is indistinguishable from nothing-happened.
//
// Mutation: drop any single check below → its case loads successfully → that subtest FAILS.
func TestAHuntThatCouldNeverMatchIsRefusedAtLoad(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantIn  string // a substring the error must name, so the operator can find the mistake
		wantErr bool
	}{
		{
			name: "a well-formed hunt",
			json: `{"hunts":[{"name":"credential-staged-then-exfiltrated",
			        "technique_sequence":["T1552","T1567.002"],"min_severity":"medium"}]}`,
		},
		{
			name: "a domain sequence alone is fine",
			json: `{"hunts":[{"name":"identity-then-exec","domain_sequence":["ueba","hips"]}]}`,
		},
		{
			name: "both sequences together",
			json: `{"hunts":[{"name":"both","domain_sequence":["dlp","nips"],
			        "technique_sequence":["T1552","T1567.002"]}]}`,
		},
		{
			name:    "a technique this build cannot derive",
			json:    `{"hunts":[{"name":"ransomware","technique_sequence":["T1486"]}]}`,
			wantIn:  "T1486",
			wantErr: true,
		},
		{
			name:    "a domain no producer emits",
			json:    `{"hunts":[{"name":"typo","domain_sequence":["ueba","hipss"]}]}`,
			wantIn:  "hipss",
			wantErr: true,
		},
		{
			// The name is the incident's identity alongside the entity. Without it the hunt's incident
			// would be indistinguishable from the breadth rule's and would collide with it.
			name:    "an unnamed hunt",
			json:    `{"hunts":[{"technique_sequence":["T1552","T1567.002"]}]}`,
			wantIn:  "no name",
			wantErr: true,
		},
		{
			// Two hunts sharing a name would merge into one incident and the second would never page —
			// the migration-045 collision, reintroduced through configuration.
			name: "duplicate names",
			json: `{"hunts":[{"name":"dup","technique_sequence":["T1552","T1567.002"]},
			        {"name":"dup","domain_sequence":["ueba","hips"]}]}`,
			wantIn:  "dup",
			wantErr: true,
		},
		{
			// A rule with no sequence is the breadth rule under another name: it would double every one
			// of its incidents, and an operator would read two incidents as two findings.
			name:    "a hunt that constrains nothing",
			json:    `{"hunts":[{"name":"everything","min_domains":2}]}`,
			wantIn:  "constrains nothing",
			wantErr: true,
		},
		{
			name:    "not a severity bucket",
			json:    `{"hunts":[{"name":"h","technique_sequence":["T1552"],"min_severity":"urgent"}]}`,
			wantIn:  "urgent",
			wantErr: true,
		},
		{
			// A MISSPELLED THRESHOLD is what DisallowUnknownFields is really for, and it is the one
			// mistake nothing else here would catch: this hunt is otherwise perfectly valid, so
			// ignoring the unknown key would load a rule that runs over the DEFAULT window while the
			// file plainly says two hours. The operator would then read its results as covering a
			// window it never used.
			name: "a misspelled threshold on an otherwise valid hunt",
			json: `{"hunts":[{"name":"h","technique_sequence":["T1552","T1567.002"],
			        "windowseconds":7200}]}`,
			wantIn:  "windowseconds",
			wantErr: true,
		},
		{
			// `techniques` where `technique_sequence` was meant is caught twice over — by the unknown
			// field and, were that removed, by constraining nothing.
			name:    "a misspelled sequence field",
			json:    `{"hunts":[{"name":"h","techniques":["T1552","T1567.002"]}]}`,
			wantErr: true,
		},
		{
			name:    "a negative window",
			json:    `{"hunts":[{"name":"h","technique_sequence":["T1552"],"window_seconds":-1}]}`,
			wantIn:  "negative",
			wantErr: true,
		},
		{
			name: "an empty file is valid and means no hunts",
			json: `{"hunts":[]}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := controlplane.LoadHunts(strings.NewReader(c.json))
			if !c.wantErr {
				if err != nil {
					t.Fatalf("LoadHunts = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("LoadHunts accepted %s — it would be deployed and match nothing, and an "+
					"operator would read that silence as an all-clear", c.name)
			}
			if !errors.Is(err, controlplane.ErrBadHunts) {
				t.Fatalf("LoadHunts = %v, want ErrBadHunts", err)
			}
			if c.wantIn != "" && !strings.Contains(err.Error(), c.wantIn) {
				t.Errorf("error %q does not name %q — %q is not actionable when several hunts are "+
					"configured", err.Error(), c.wantIn, err.Error())
			}
			_ = h
		})
	}
}

// A hunt states only what makes it different from the breadth rule; the tick's defaults fill the rest.
func TestAHuntInheritsTheTicksDefaultsUnlessItOverridesThem(t *testing.T) {
	h, err := controlplane.LoadHunts(strings.NewReader(`{"hunts":[
	  {"name":"inherits","technique_sequence":["T1552","T1567.002"]},
	  {"name":"overrides","domain_sequence":["ueba","hips"],"window_seconds":7200,"min_domains":3,
	   "min_severity":"high"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rules := h.Rules(time.Hour, 2, 168*time.Hour)
	if len(rules) != 2 {
		t.Fatalf("Rules returned %d, want 2", len(rules))
	}

	in := rules[0]
	if in.Name != "inherits" || in.Window != time.Hour || in.MinDomains != 2 {
		t.Errorf("inherited rule = %+v, want the tick's window and domain minimum", in)
	}
	if len(in.TechniqueSequence) != 2 || in.TechniqueSequence[0] != "T1552" {
		t.Errorf("technique sequence = %v, want [T1552 T1567.002]", in.TechniqueSequence)
	}
	if in.RecurrenceWindow != 168*time.Hour {
		t.Errorf("recurrence window = %v, want the lifecycle default — recurrence is a property of the "+
			"incident, not of the narrative, so a hunt cannot set it", in.RecurrenceWindow)
	}

	ov := rules[1]
	if ov.Window != 2*time.Hour || ov.MinDomains != 3 || ov.MinSeverity != "high" {
		t.Errorf("overriding rule = %+v, want its own window/minimum/floor", ov)
	}
	if len(ov.Sequence) != 2 || ov.Sequence[1] != "hips" {
		t.Errorf("domain sequence = %v, want [ueba hips]", ov.Sequence)
	}
}
