package config_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/config"
)

// Resolver.Bool is how every on/off setting in the product is read, and it DISCARDS the parse error:
//
//	func (r *Resolver) Bool(key string) bool { b, _ := strconv.ParseBool(r.String(key)); return b }
//
// So an unparseable value is silently false. That is the correct choice here and it is worth pinning down
// rather than leaving to the next person's judgement, because the tempting "fix" — treating anything
// non-empty as true, or defaulting a malformed value to true — would turn a typo into ENABLED. Under D1
// the product is observe-only by default and enforcement is opt-in, so the safe direction for an
// unreadable value is OFF. Validate() is what tells the operator their value was rejected; Bool's job is
// only to be safe when it was.
func TestBoolParsesTheAcceptedSpellingsAndIsFalseForEverythingElse(t *testing.T) {
	const key = "OPENSHIELD_TEST_FLAG"

	for _, tc := range []struct {
		raw  string
		want bool
	}{
		// Accepted by strconv.ParseBool.
		{"true", true}, {"TRUE", true}, {"True", true}, {"t", true}, {"T", true}, {"1", true},
		{"false", false}, {"FALSE", false}, {"f", false}, {"0", false},

		// Everything else is OFF. "yes"/"on" are the ones people actually type, and they do NOT enable.
		{"yes", false}, {"YES", false}, {"on", false}, {"enabled", false},
		{"truthy", false}, {"tru", false}, {"2", false}, {"-1", false},
		{"", false}, {" ", false}, {" true", false}, {"true ", false},
	} {
		t.Run("value="+tc.raw, func(t *testing.T) {
			r := config.New([]config.Field{
				{Key: key, Scope: config.ScopeBootstrap, Kind: config.KindBool, Default: tc.raw},
			})
			if got := r.Bool(key); got != tc.want {
				t.Fatalf("Bool(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// READING AN UNDECLARED KEY PANICS, and that is the design rather than an oversight — I assumed the
// opposite when writing this test and the code corrected me.
//
// The schema this product shows an operator is DERIVED from the declared field set, so a field that code
// reads but nobody declared would be invisible in the UI: unsettable, undocumented, and silently taking
// its zero value on every deployment. raw() refuses to make that reachable, the same way New() panics on a
// duplicate declaration. Both are programming errors caught at the first read rather than drift discovered
// in production.
//
// Pinned as a test because the tempting "hardening" is to return the zero value instead, which would trade
// a loud panic on a code path nobody shipped for exactly the invisible field the panic exists to prevent.
func TestReadingAnUndeclaredFieldPanicsRatherThanReturningAZeroValue(t *testing.T) {
	for name, read := range map[string]func(*config.Resolver){
		"Bool":     func(r *config.Resolver) { _ = r.Bool("OPENSHIELD_NOT_A_REAL_KEY") },
		"String":   func(r *config.Resolver) { _ = r.String("OPENSHIELD_NOT_A_REAL_KEY") },
		"Duration": func(r *config.Resolver) { _ = r.Duration("OPENSHIELD_NOT_A_REAL_KEY") },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s on an undeclared key returned a zero value instead of panicking — a field "+
						"read by code but declared nowhere is invisible to the config UI and unsettable by "+
						"any operator", name)
				}
			}()
			read(config.New(nil))
		})
	}
}

// DBSource is the ONLY source for a dynamic field, and Snapshot()/Name() are how the rest of the system
// reads it. NewDBSource must start with an EMPTY snapshot rather than nil: a deployment that has never
// written a setting still resolves every dynamic field to its default, and a nil map here would be the
// difference between "use the default" and a panic on first lookup.
func TestADBSourceStartsEmptyAndSwapsAtomically(t *testing.T) {
	d := config.NewDBSource()

	if d.Name() != "db" {
		t.Fatalf("Name() = %q, want \"db\" — the origin string an operator reads to see WHERE a value "+
			"came from", d.Name())
	}
	snap := d.Snapshot()
	if snap == nil {
		t.Fatal("a fresh DBSource has a nil snapshot")
	}
	if snap.Values == nil {
		t.Fatal("a fresh DBSource has a nil Values map")
	}
	if len(snap.Values) != 0 || snap.Revision != 0 {
		t.Fatalf("a fresh DBSource is not empty: %+v", snap)
	}
	if _, ok := d.Lookup("anything"); ok {
		t.Fatal("an empty DBSource answered a lookup")
	}

	d.Set(&config.Snapshot{Revision: 7, Values: map[string]string{"OPENSHIELD_X": "42"}})
	if got := d.Snapshot(); got.Revision != 7 || got.Values["OPENSHIELD_X"] != "42" {
		t.Fatalf("Snapshot() returned %+v after Set", got)
	}
	if d.Revision() != 7 {
		t.Fatalf("Revision() = %d, want 7 — this is the answer to \"has this host caught up\"", d.Revision())
	}
	if v, ok := d.Lookup("OPENSHIELD_X"); !ok || v != "42" {
		t.Fatalf("Lookup after Set returned %q, %v", v, ok)
	}

	// An empty string is NOT a value: Lookup reports it as absent so the field falls through to its
	// default, rather than resolving to "".
	d.Set(&config.Snapshot{Revision: 8, Values: map[string]string{"OPENSHIELD_X": ""}})
	if _, ok := d.Lookup("OPENSHIELD_X"); ok {
		t.Fatal("an empty stored value was reported as present, shadowing the field's default")
	}
}
