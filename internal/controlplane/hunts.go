package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/lucianoengel/openshield/internal/attack"
)

// Scheduled hunts (XDR-4c).
//
// XDR-4's ordered-sequence rule — the half of cross-domain correlation that makes an attack NARRATIVE
// claim rather than a breadth claim — was set in exactly one place in the tree outside tests: the
// GET /incidents query parser. The scheduled correlation loop, whose whole justification is that "an
// incident existed only if a human happened to look… detection has to run on a clock", constructed its
// CrossDomainRule with Window/MinDomains/RecurrenceWindow and left Sequence at its zero value.
//
// So the platform could ANSWER "did T1552 then T1567.002 happen on this asset?" for an operator who
// already suspected it, and could never TELL anyone. No sequence match had ever raised an incident,
// paged a human, opened a case or started an escalation ladder.
//
// A hunt is that rule, named and configured, run on the same tick as the breadth rule.

// Hunt is one configured narrative rule as written in the hunts file.
//
// The wire shape is separate from CrossDomainRule because the file speaks in seconds (JSON has no
// duration) and because a hunt is a strict subset: it cannot set a recurrence window, which belongs to
// the incident lifecycle rather than to the narrative being hunted.
type Hunt struct {
	Name              string   `json:"name"`
	DomainSequence    []string `json:"domain_sequence,omitempty"`
	TechniqueSequence []string `json:"technique_sequence,omitempty"`
	WindowSeconds     int      `json:"window_seconds,omitempty"`
	MinDomains        int      `json:"min_domains,omitempty"`
	MinSeverity       string   `json:"min_severity,omitempty"`
}

// Hunts is a parsed, validated hunt file.
type Hunts struct {
	Hunts []Hunt `json:"hunts"`
}

// ErrBadHunts is a structurally invalid or unsatisfiable hunt file.
var ErrBadHunts = errors.New("controlplane: invalid correlation hunts")

// LoadHunts parses and VALIDATES a hunt file against the real domain and technique vocabularies.
//
// Validated at LOAD, for the reason the HTTP handler already refuses the same inputs: a step naming
// something no producer can emit would never match, and the operator would read the resulting silence
// as "that attack chain did not happen". The failure is WORSE here than on the interactive path — an
// ad-hoc query at least returns a 400 immediately, while a mistyped hunt sits in the deployed file
// matching nothing for as long as it is configured.
//
// Every rejection names the hunt and the offending value. "hunts failed to load" is not actionable.
func LoadHunts(r io.Reader) (Hunts, error) {
	var h Hunts
	dec := json.NewDecoder(r)
	// Unknown fields are refused rather than ignored: a hunt with `techniques` where
	// `technique_sequence` was meant would otherwise load as an unconstrained rule and duplicate the
	// breadth rule's incidents under a name that claims a narrative it never checked.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return Hunts{}, fmt.Errorf("%w: %v", ErrBadHunts, err)
	}
	seen := map[string]bool{}
	for i := range h.Hunts {
		hunt := &h.Hunts[i]
		// The name is the incident's identity alongside the entity (migration 045). An empty or
		// duplicate name would merge two hunts into one incident and silence the second's page —
		// exactly the collision this ticket's schema change exists to prevent, reintroduced through
		// configuration.
		if hunt.Name == "" {
			return Hunts{}, fmt.Errorf("%w: hunt %d has no name, and the name is the incident's identity",
				ErrBadHunts, i)
		}
		if seen[hunt.Name] {
			return Hunts{}, fmt.Errorf("%w: two hunts are named %q; the second would merge into the "+
				"first's incident and never page", ErrBadHunts, hunt.Name)
		}
		seen[hunt.Name] = true
		// A hunt with neither sequence is the breadth rule under another name. It would raise a second,
		// identical incident for every entity the breadth rule already caught, and an operator would
		// reasonably read two incidents as two findings.
		if len(hunt.DomainSequence) == 0 && len(hunt.TechniqueSequence) == 0 {
			return Hunts{}, fmt.Errorf("%w: hunt %q constrains nothing — a rule with no sequence is the "+
				"breadth rule under another name and would double every one of its incidents",
				ErrBadHunts, hunt.Name)
		}
		for _, step := range hunt.DomainSequence {
			if !knownDomain(step) {
				return Hunts{}, fmt.Errorf("%w: hunt %q names domain %s, which no producer emits — it "+
					"would match nothing and the silence would read as an all-clear",
					ErrBadHunts, hunt.Name, strconv.Quote(step))
			}
		}
		for _, step := range hunt.TechniqueSequence {
			if !attack.Known(step) {
				return Hunts{}, fmt.Errorf("%w: hunt %q names technique %s, which this build cannot "+
					"derive — it would match nothing and the silence would read as an all-clear",
					ErrBadHunts, hunt.Name, strconv.Quote(step))
			}
		}
		if hunt.MinSeverity != "" {
			if _, ok := severityFloor(hunt.MinSeverity); !ok {
				return Hunts{}, fmt.Errorf("%w: hunt %q: %s is not a severity bucket",
					ErrBadHunts, hunt.Name, strconv.Quote(hunt.MinSeverity))
			}
		}
		if hunt.WindowSeconds < 0 || hunt.MinDomains < 0 {
			return Hunts{}, fmt.Errorf("%w: hunt %q has a negative window or domain minimum",
				ErrBadHunts, hunt.Name)
		}
	}
	return h, nil
}

// Rules turns the file's hunts into correlation rules, filling each unset threshold from the tick's
// defaults so a hunt only has to state what makes it different from the breadth rule.
//
// The recurrence window is NOT a per-hunt setting: it governs how far back a closed incident counts as
// this one's predecessor, which is a property of the incident lifecycle rather than of the narrative.
func (h Hunts) Rules(defaultWindow time.Duration, defaultMinDomains int, recurrence time.Duration) []CrossDomainRule {
	out := make([]CrossDomainRule, 0, len(h.Hunts))
	for _, hunt := range h.Hunts {
		r := CrossDomainRule{
			Name:              hunt.Name,
			Window:            defaultWindow,
			MinDomains:        defaultMinDomains,
			MinSeverity:       hunt.MinSeverity,
			Sequence:          hunt.DomainSequence,
			TechniqueSequence: hunt.TechniqueSequence,
			RecurrenceWindow:  recurrence,
		}
		if hunt.WindowSeconds > 0 {
			r.Window = time.Duration(hunt.WindowSeconds) * time.Second
		}
		if hunt.MinDomains > 0 {
			r.MinDomains = hunt.MinDomains
		}
		out = append(out, r)
	}
	return out
}
