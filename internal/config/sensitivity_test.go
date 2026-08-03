package config_test

import (
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/config"
)

// SEC-A: `grep "Validate:" internal/config/*.go` outside tests returned ZERO. The entire per-field bound
// was the Kind's parseability, so "is this a duration" was the whole check on the values that decide
// whether anything is detected at all.
//
// At single-admin tier, over POST /config, with no four-eyes and no TTL, every one of these is a valid
// value that turns the product off.

func fieldFor(t *testing.T, key string) config.Field {
	t.Helper()
	for _, f := range config.ServerFields {
		if f.Key == key {
			return f
		}
	}
	t.Fatalf("%s is not declared in ServerFields", key)
	return config.Field{}
}

// TestTheValuesThatNeuterTheProductAreRefused.
//
// Each of these was accepted before, and each has a specific consequence named in the roadmap. They are
// asserted together because the defect was not four separate oversights — it was that no field declared
// a bound at all.
//
// Mutation: remove any one Validate → that case FAILS.
func TestTheValuesThatNeuterTheProductAreRefused(t *testing.T) {
	for _, tc := range []struct {
		key, value, consequence string
	}{
		{"OPENSHIELD_CORRELATE_INTERVAL", "8760h",
			"a correlation sweep once a year means no incident is ever raised without an operator asking"},
		{"OPENSHIELD_OVERDUE_THRESHOLD", "8760h",
			"an agent killed by an attacker is never reported missing — the dead-man's-switch is the " +
				"only thing that reports it"},
		{"OPENSHIELD_FLEET_RETENTION", "1h",
			"evidence is purged through a SANCTIONED delete path the ledger's hash chain does not cover"},
		{"OPENSHIELD_RETENTION_INTERVAL", "1s",
			"a purge running every second is a shredder pointed at the evidence store"},
		{"OPENSHIELD_BEACON_MIN_CONTACTS", "2",
			"two contacts give one interval, and one interval is always perfectly regular"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			f := fieldFor(t, tc.key)
			if f.Validate == nil {
				t.Fatalf("%s declares no bound at all — its only check is whether the value parses", tc.key)
			}
			err := f.Check(tc.value)
			if err == nil {
				t.Fatalf("%s=%s was accepted. %s", tc.key, tc.value, tc.consequence)
			}
			// The refusal must explain the consequence, not just cite a limit. An operator told
			// "must be <= 6h" routes around the rule; one told what breaks does not.
			if len(err.Error()) < 40 {
				t.Errorf("the refusal is too terse to act on: %q", err)
			}
		})
	}
}

// TestOrdinaryValuesAreStillAccepted. A bound that refuses reasonable settings is a bound that gets
// removed, so the operator's actual range is asserted as deliberately as the attack.
func TestOrdinaryValuesAreStillAccepted(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"OPENSHIELD_CORRELATE_INTERVAL", "5m"},
		{"OPENSHIELD_CORRELATE_INTERVAL", "0s"}, // documented as "disables it" — a stated choice, not a bound violation
		{"OPENSHIELD_OVERDUE_THRESHOLD", "15m"},
		{"OPENSHIELD_OVERDUE_THRESHOLD", "6h"},
		{"OPENSHIELD_FLEET_RETENTION", "2160h"},
		{"OPENSHIELD_FLEET_RETENTION", "24h"},
		{"OPENSHIELD_RETENTION_INTERVAL", "24h"},
		{"OPENSHIELD_BEACON_MIN_CONTACTS", "8"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			if err := fieldFor(t, tc.key).Check(tc.value); err != nil {
				t.Errorf("a legitimate setting was refused: %v", err)
			}
		})
	}
}

// TestEveryDefaultSatisfiesItsOwnBound. A default outside its own declared range is a bug in the schema
// that would fail every boot, and finding it here is cheaper than finding it there.
func TestEveryDefaultSatisfiesItsOwnBound(t *testing.T) {
	for _, set := range [][]config.Field{
		config.ServerFields, config.GatewayFields, config.EngineFields,
		config.AgentFields, config.WorkerFields, config.FleetAgentFields,
	} {
		for _, f := range set {
			if f.Validate == nil || f.Default == "" {
				continue
			}
			if err := f.Validate(f.Default); err != nil {
				t.Errorf("%s's DEFAULT %q violates its own bound: %v", f.Key, f.Default, err)
			}
		}
	}
}

// TestWeakeningIsComputable is the half a bound cannot cover.
//
// Most of these attacks use values that are perfectly reasonable in isolation: a 24-hour retention is a
// legitimate choice, and a suspicious one on the day an incident is opened. No bound can refuse it. What
// the audit trail was missing is the DIRECTION — whether a change reduced what the deployment can see —
// and that is not a matter of opinion.
//
// Mutation: invert either direction, or make Weakens always false → this FAILS.
func TestWeakeningIsComputable(t *testing.T) {
	for _, tc := range []struct {
		key, from, to string
		want          bool
		why           string
	}{
		{"OPENSHIELD_OVERDUE_THRESHOLD", "15m", "6h", true, "tolerating six hours of silence from a host"},
		{"OPENSHIELD_OVERDUE_THRESHOLD", "6h", "15m", false, "noticing a silent host sooner"},
		{"OPENSHIELD_FLEET_RETENTION", "2160h", "48h", true, "keeping three months of evidence became two days"},
		{"OPENSHIELD_FLEET_RETENTION", "48h", "2160h", false, "keeping more evidence"},
		{"OPENSHIELD_CORRELATE_WINDOW", "1h", "10m", true, "a narrower look-back correlates less"},
		{"OPENSHIELD_BEACON_ALLOWLIST", "", "cdn.example.com", true,
			"an added allowlist entry is the whole attack, and no comparison of two strings can tell a " +
				"C2 domain from a CDN"},
		{"OPENSHIELD_BEACON_ALLOWLIST", "a.example", "a.example", false, "no change at all"},
	} {
		t.Run(tc.key+" "+tc.from+"->"+tc.to, func(t *testing.T) {
			if got := fieldFor(t, tc.key).Weakens(tc.from, tc.to); got != tc.want {
				t.Errorf("Weakens(%q,%q) = %v, want %v — %s", tc.from, tc.to, got, tc.want, tc.why)
			}
		})
	}
}

// TestDisablingSortsAsTheWeakestSetting is the case the whole classification exists for, and the one an
// ordinary numeric comparison gets exactly backwards.
//
// OPENSHIELD_CORRELATE_INTERVAL=0s does not mean "correlate infinitely often". Its own description says
// zero disables it. Ordered numerically, the single change that stops incidents being raised at all
// would score as the most aggressive possible setting — the attack reported as a hardening.
//
// Mutation: drop ZeroDisables from the field, or ignore it in magnitude() → this FAILS.
func TestDisablingSortsAsTheWeakestSetting(t *testing.T) {
	f := fieldFor(t, "OPENSHIELD_CORRELATE_INTERVAL")
	if !f.Weakens("5m", "0s") {
		t.Error("turning scheduled correlation OFF did not register as weakening — read as a number, " +
			"zero is the smallest interval and therefore the most aggressive setting, which is how the " +
			"one change that raises no incidents at all reports as a hardening")
	}
	if f.Weakens("0s", "5m") {
		t.Error("turning correlation ON registered as weakening")
	}
}

// TestEveryDetectionFieldDeclaresItsDirection is the durable half.
//
// The bounds fix the four values the review named. This is what stops the fifth: a new detector's
// threshold, added next month, that nobody classifies — and which is therefore silently claimed to be
// irrelevant to detection, because NotSensitive is the zero value.
//
// The expected set is written out rather than inferred from a name pattern, so ADDING a dynamic
// detection field forces someone to decide which way it points, and REMOVING one is equally visible. A
// heuristic on key names would have gone stale on the first field called something else.
func TestEveryDetectionFieldDeclaresItsDirection(t *testing.T) {
	want := map[string]config.Sensitivity{
		"OPENSHIELD_BEACON_INTERVAL":         config.RaisingWeakens,
		"OPENSHIELD_BEACON_WINDOW":           config.LoweringWeakens,
		"OPENSHIELD_BEACON_MIN_CONTACTS":     config.RaisingWeakens,
		"OPENSHIELD_BEACON_MIN_REGULARITY":   config.RaisingWeakens,
		"OPENSHIELD_BEACON_ALLOWLIST":        config.AnyChangeWeakens,
		"OPENSHIELD_CORRELATE_INTERVAL":      config.RaisingWeakens,
		"OPENSHIELD_CORRELATE_WINDOW":        config.LoweringWeakens,
		"OPENSHIELD_CORRELATE_MIN_ALERTS":    config.RaisingWeakens,
		"OPENSHIELD_CORRELATE_MIN_DOMAINS":   config.RaisingWeakens,
		"OPENSHIELD_OVERDUE_THRESHOLD":       config.RaisingWeakens,
		"OPENSHIELD_OVERDUE_INTERVAL":        config.RaisingWeakens,
		"OPENSHIELD_RETENTION_INTERVAL":      config.RaisingWeakens,
		"OPENSHIELD_FLEET_RETENTION":         config.LoweringWeakens,
		"OPENSHIELD_NOTIFY_DEDUPE_RETENTION": config.LoweringWeakens,
		"OPENSHIELD_PEER_UEBA_THRESHOLD":     config.RaisingWeakens,
		"OPENSHIELD_PEER_UEBA_COOLDOWN":      config.RaisingWeakens,
		"OPENSHIELD_ALERT_ROUTES":            config.AnyChangeWeakens,
	}
	got := map[string]config.Sensitivity{}
	for _, f := range config.ServerFields {
		if f.Sensitivity != config.NotSensitive {
			got[f.Key] = f.Sensitivity
		}
	}
	for k, w := range want {
		if g, ok := got[k]; !ok {
			t.Errorf("%s no longer declares a direction — a detection setting whose direction is "+
				"undeclared is silently claimed to be irrelevant to detection, because NotSensitive is "+
				"the zero value", k)
		} else if g != w {
			t.Errorf("%s declares %v, expected %v", k, g, w)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s newly declares a direction and is not in this list. Add it — the list is what "+
				"makes the classification a decision rather than a default", k)
		}
	}
}

// TestABoundNeverReportsAParseError. Kind parseability and operational range are separate checks, and a
// bound that also complains about syntax produces two errors for one typo — one of which points at the
// wrong thing.
func TestABoundNeverReportsAParseError(t *testing.T) {
	f := fieldFor(t, "OPENSHIELD_OVERDUE_THRESHOLD")
	if err := f.Validate("not-a-duration"); err != nil {
		t.Errorf("the bound reported %v for an unparseable value — that is the Kind's error to give, "+
			"and giving it twice puts a range complaint on a syntax mistake", err)
	}
	// The Kind still catches it, through the path a write actually takes.
	if err := f.Check("not-a-duration"); err == nil || !strings.Contains(err.Error(), "duration") {
		t.Errorf("Check accepted an unparseable duration or misreported it: %v", err)
	}
}
