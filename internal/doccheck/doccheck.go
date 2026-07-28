// Package doccheck guards the project's honesty on its claim surfaces (T-029).
//
// The project's credibility rests on "tamper-evident, not tamper-proof" and
// "detection, not prevention". A careless README edit could erase that. But the
// naive guard is worse than none: a denylist grep for the forbidden words
// false-positived on four HONEST negated uses (2026-07-20), because this
// project's discipline consists of discussing exactly those words in negation.
// So this check tells a claim from its denial: it flags an UNQUALIFIED overclaim
// and passes negated discussion, an escaped use, and the docs that exist to
// reason out loud.
package doccheck

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ClaimSurfaces is the explicit allowlist of files a claim can be made on. It is
// an allowlist, not "all docs", because docs/ is where the project reasons out
// loud — including about what it CANNOT do — and scanning it would recreate the
// false-positive failure the naive grep suffered.
var ClaimSurfaces = []string{"README.md", "CHANGELOG.md"}

// forbidden are overclaiming terms, each mapping to a specific false promise the
// threat model forbids: tamper-proofing, prevention, absolutes. Matched
// case-insensitively after markdown emphasis is stripped.
var forbidden = []*regexp.Regexp{
	regexp.MustCompile(`(?i)tamper-?proof`),
	regexp.MustCompile(`(?i)unhackable`),
	regexp.MustCompile(`(?i)impenetrable`),
	regexp.MustCompile(`(?i)(?:fully|100%) secure`),
	regexp.MustCompile(`(?i)prevents (?:exfiltration|data loss)`),
	regexp.MustCompile(`(?i)guarantees? (?:security|safety|protection|your data)`),
}

// negation marks a line as discussion rather than a claim. "not", "cannot",
// "impossible" etc. are exactly how the honest README states its limits.
var negation = regexp.MustCompile(`(?i)\b(cannot|can't|not|never|no|isn't|impossible|does ?n't|without)\b`)

// emphasis is markdown bold/italic markers, stripped before matching so
// `tamper-*proof*` is caught the same as `tamperproof`.
var emphasis = regexp.MustCompile(`[*_]`)

// allowEscape permits a deliberate use: `<!-- allow: <term> -->`.
var allowEscape = regexp.MustCompile(`<!--\s*allow:\s*(.+?)\s*-->`)

// Violation is one unqualified overclaim.
type Violation struct {
	Line int
	Term string
	Text string
}

func (v Violation) String() string {
	return fmt.Sprintf("line %d: unqualified overclaim %q in: %s", v.Line, v.Term, strings.TrimSpace(v.Text))
}

// ScanClaimSurface reports unqualified overclaims. A match is suppressed when the
// line is negated, or carries an allow-escape on it or the line immediately
// above.
func ScanClaimSurface(text string) []Violation {
	lines := strings.Split(text, "\n")
	var out []Violation
	for i, raw := range lines {
		clean := emphasis.ReplaceAllString(raw, "")

		// Escape on this line or the one above.
		escaped := map[string]bool{}
		collectEscapes(raw, escaped)
		if i > 0 {
			collectEscapes(lines[i-1], escaped)
		}

		negated := negation.MatchString(clean)

		for _, re := range forbidden {
			m := re.FindString(clean)
			if m == "" {
				continue
			}
			if negated {
				continue // discussion, not a claim
			}
			if escaped[strings.ToLower(strings.TrimSpace(m))] || escapedAny(escaped) {
				continue
			}
			out = append(out, Violation{Line: i + 1, Term: m, Text: raw})
		}
	}
	return out
}

func collectEscapes(line string, into map[string]bool) {
	for _, m := range allowEscape.FindAllStringSubmatch(line, -1) {
		into[strings.ToLower(strings.TrimSpace(m[1]))] = true
	}
}

// escapedAny reports whether a bare `<!-- allow: ... -->` was present; a term
// escape covers any forbidden match on its line, since the author has signalled
// a deliberate discussion there.
func escapedAny(escaped map[string]bool) bool { return len(escaped) > 0 }

var dNumber = regexp.MustCompile(`\*\*D(\d+)\*\*`)

// CheckDecisionRegister fails if any D-number is assigned more than once. A
// duplicate is the drift that lets the single source of truth quietly diverge —
// two decisions colliding on a number, or a copy-paste that reused one.
func CheckDecisionRegister(text string) error {
	seen := map[string]int{}
	for _, m := range dNumber.FindAllStringSubmatch(text, -1) {
		seen[m[1]]++
	}
	var dups []string
	for n, count := range seen {
		if count > 1 {
			dups = append(dups, fmt.Sprintf("D%s (x%d)", n, count))
		}
	}
	if len(dups) > 0 {
		return fmt.Errorf("decision register has duplicate D-numbers: %s", strings.Join(dups, ", "))
	}
	return nil
}

// requirementHeading matches a capability requirement heading in a spec or a change delta.
var requirementHeading = regexp.MustCompile(`(?m)^### Requirement: (.+)$`)

// deltaSection matches a delta's operation heading.
var deltaSection = regexp.MustCompile(`(?m)^## (\w+) Requirements`)

// knownSections are the delta operations this check implements. An unrecognized one is an ERROR rather
// than a skip — refusing is what forced REMOVED and RENAMED to be implemented instead of silently
// dropped (D323), and skipping a section is how 170 requirements were lost in the first place (D322).
// activePrefix marks a change that has not been archived yet (see readSpecStore).
const activePrefix = "~active/"

var knownSections = map[string]bool{"ADDED": true, "MODIFIED": true, "REMOVED": true, "RENAMED": true}

// renameFrom and renameTo read the FROM:/TO: lines of a RENAMED section, which names its requirements
// in prose rather than in headings.
var (
	renameFrom = regexp.MustCompile(`(?mi)^\s*[-*]?\s*\**FROM\**:\s*` + "`?" + `### Requirement: (.+?)` + "`?" + `\s*$`)
	renameTo   = regexp.MustCompile(`(?mi)^\s*[-*]?\s*\**TO\**:\s*` + "`?" + `### Requirement: (.+?)` + "`?" + `\s*$`)
)

// SpecGap is one requirement an archived change introduced that its capability spec no longer holds.
type SpecGap struct {
	Capability  string
	Requirement string
	Change      string // the archived change that introduced it
}

func (g SpecGap) String() string {
	return fmt.Sprintf("%s: %q — introduced by %s, absent from openspec/specs/%s/spec.md",
		g.Capability, g.Requirement, g.Change, g.Capability)
}

// CheckSpecStore reports requirements that an archived change introduced and that its capability spec
// no longer contains.
//
// The spec store lost 170 of 526 requirements before this existed, through two failures that both
// report success: archiving a change without syncing its delta, and a sync that OVERWROTE the
// capability file with the delta being merged into it. `openspec/specs/control-plane/spec.md` was
// reduced to a single requirement — the body of one delta — while thirty-six other changes' work
// simply vanished. Nobody noticed, because nothing failed.
//
// The check is deliberately narrow: it compares HEADINGS only. Comparing bodies would fail on
// requirements a capability file has legitimately reworded, and a guard that must be suppressed is a
// guard that gets deleted. It also does not care about requirements a capability holds with no
// archived source — authoring a requirement directly is allowed.
//
// deltas maps an archived change name to that change's delta files, keyed by capability; specs maps a
// capability to its merged spec text. Reading the tree is the caller's job so this stays testable
// against fixtures.
func CheckSpecStore(deltas map[string]map[string]string, specs map[string]string) ([]SpecGap, error) {
	changes := make([]string, 0, len(deltas))
	for change := range deltas {
		changes = append(changes, change)
	}
	// Chronological: archive directories are date-prefixed, so lexical order is date order.
	sort.Strings(changes)

	type state struct {
		op     string // the LAST operation applied to this requirement
		change string
	}
	current := map[[2]string]state{}
	order := make([][2]string, 0)
	note := func(capability, requirement, op, change string) {
		key := [2]string{capability, requirement}
		if _, seen := current[key]; !seen {
			order = append(order, key)
		}
		current[key] = state{op: op, change: change}
	}

	for _, change := range changes {
		for capability, text := range deltas[change] {
			sections := deltaSection.FindAllStringSubmatchIndex(text, -1)
			for _, s := range sections {
				if name := text[s[2]:s[3]]; !knownSections[name] {
					return nil, fmt.Errorf("%s/%s: unrecognized delta section %q — refusing to "+
						"ignore it, because ignoring a section is how requirements were lost",
						change, capability, name)
				}
			}
			sectionAt := func(pos int) string {
				op := "ADDED"
				for _, s := range sections {
					if s[0] < pos {
						op = text[s[2]:s[3]]
					} else {
						break
					}
				}
				return op
			}
			// An ACTIVE change is a PROPOSAL, and its deltas are honoured only where they RELAX.
			//
			// Its REMOVED entries must count, or retiring a requirement leaves the gate red for the whole
			// life of the work that retires it. Its ADDED entries must NOT, because demanding a
			// not-yet-shipped requirement be present in the capability file inverts the workflow: the
			// sync happens at archive, so the gate would be red from the moment a change is proposed
			// until the moment it lands. Both directions of that were learned the hard way — a guard
			// that blocks ordinary work is a guard someone switches off.
			active := strings.HasPrefix(change, activePrefix)
			for _, m := range requirementHeading.FindAllStringSubmatchIndex(text, -1) {
				op := sectionAt(m[0])
				if active && op != "REMOVED" {
					continue
				}
				note(capability, strings.TrimSpace(text[m[2]:m[3]]), op, change)
			}
			// A rename retires the old heading and puts the new one in force.
			for _, m := range renameFrom.FindAllStringSubmatch(text, -1) {
				note(capability, strings.TrimSpace(m[1]), "REMOVED", change)
			}
			for _, m := range renameTo.FindAllStringSubmatch(text, -1) {
				if active {
					continue // the new heading is not required until the change lands
				}
				note(capability, strings.TrimSpace(m[1]), "ADDED", change)
			}
		}
	}

	var gaps []SpecGap
	for _, key := range order {
		capability, requirement := key[0], key[1]
		// A requirement a later change RETIRED is correctly absent. Without this, removing anything
		// would be impossible without switching the guard off — and a check that must be switched off
		// to do ordinary work does not survive contact with ordinary work.
		if current[key].op == "REMOVED" {
			continue
		}
		if spec, ok := specs[capability]; ok && strings.Contains(spec, "### Requirement: "+requirement) {
			continue
		}
		gaps = append(gaps, SpecGap{Capability: capability, Requirement: requirement, Change: current[key].change})
	}
	return gaps, nil
}
