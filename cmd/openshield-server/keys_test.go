package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// cmd/openshield-server is the control plane, 1236 lines, and had no test file. These are the pure parts:
// the verb that can disable enforcement across a whole fleet, and the key loaders that decide whether a
// signature can be checked at all.

// fleetVerb parses the FLEET-WIDE enforcement switch. A verb it does not recognise must be REFUSED, and
// the refusal is the entire safety property: a parser that fell through to a default would let a typo
// (`--verb disbale`, `--verb off`, an empty flag) disable enforcement across every endpoint, which is the
// single most destructive thing this binary can be asked to do.
func TestFleetVerbIsAClosedVocabulary(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want corev1.FleetVerb
	}{
		{"disable", corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_DISABLE},
		{"restore", corev1.FleetVerb_FLEET_VERB_ENFORCEMENT_RESTORE},
	} {
		got, ok := fleetVerb(tc.in)
		if !ok || got != tc.want {
			t.Fatalf("fleetVerb(%q) = %v, %v; want %v, true", tc.in, got, ok, tc.want)
		}
	}

	for _, in := range []string{
		"", " ", "disbale", "off", "on", "DISABLE", "Disable", "disable ", "enforcement-disable",
		"restore-all", "stop", "0", "true", "--verb",
	} {
		got, ok := fleetVerb(in)
		if ok {
			t.Fatalf("fleetVerb(%q) was ACCEPTED as %v — an unrecognised verb must be refused, or a typo "+
				"disables enforcement across the whole fleet", in, got)
		}
		// And the refused value must be UNSPECIFIED, not a real verb a careless caller might act on.
		if got != corev1.FleetVerb_FLEET_VERB_UNSPECIFIED {
			t.Fatalf("fleetVerb(%q) returned %v alongside ok=false; a caller ignoring ok would act on it",
				in, got)
		}
	}
}

func writeKey(t *testing.T, dir, name string, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A key of the WRONG LENGTH must be refused rather than used. ed25519 operations on a short or padded key
// do not fail cleanly — they panic or verify nothing — so the length check is what turns a truncated file
// or a base64-vs-raw mix-up into a startup error naming the file, instead of a crash mid-incident or a
// signature check that silently accepts everything.
func TestKeyLoadersRefuseTheWrongLength(t *testing.T) {
	dir := t.TempDir()

	for name, tc := range map[string]struct {
		env    string
		load   func() (int, error)
		size   int
		isPriv bool
	}{
		"intent signing (private)": {
			env:  "OPENSHIELD_RISK_SIGNING_KEY",
			load: func() (int, error) { k, err := intentSigningKey(); return len(k), err },
			size: ed25519.PrivateKeySize,
		},
		"TI feed (public)": {
			env:  "OPENSHIELD_TI_FEED_KEY",
			load: func() (int, error) { k, err := feedVerificationKey(); return len(k), err },
			size: ed25519.PublicKeySize,
		},
		"intent verification (public)": {
			env:  "OPENSHIELD_INTENT_KEY",
			load: func() (int, error) { k, err := intentVerificationKey(); return len(k), err },
			size: ed25519.PublicKeySize,
		},
	} {
		t.Run(name, func(t *testing.T) {
			// UNSET is not an error: it means the feature is off, and each caller decides what that
			// implies (for intents, the responder does not start at all).
			t.Setenv(tc.env, "")
			if n, err := tc.load(); err != nil || n != 0 {
				t.Fatalf("an unset key gave (%d, %v); want (0, nil) — unset means the feature is off, "+
					"not misconfigured", n, err)
			}

			// The right length loads.
			t.Setenv(tc.env, writeKey(t, dir, name+".good", tc.size))
			if n, err := tc.load(); err != nil || n != tc.size {
				t.Fatalf("a correctly sized key gave (%d, %v)", n, err)
			}

			// Every wrong length is refused, INCLUDING an empty file and one that is off by a single byte.
			for _, bad := range []int{0, 1, tc.size - 1, tc.size + 1, tc.size / 2, tc.size * 2} {
				if bad < 0 {
					continue
				}
				t.Setenv(tc.env, writeKey(t, dir, name+".bad", bad))
				n, err := tc.load()
				if err == nil {
					t.Fatalf("a %d-byte key was accepted for a %d-byte slot (got %d bytes back); ed25519 "+
						"does not fail cleanly on a wrong-sized key", bad, tc.size, n)
				}
			}

			// A path that does not exist is an error naming the file, not a silent "feature off".
			t.Setenv(tc.env, filepath.Join(dir, "definitely-absent"))
			if _, err := tc.load(); err == nil {
				t.Fatal("a missing key file was treated as if the feature were simply unconfigured")
			}
		})
	}
}

func TestSplitCSV(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{",", nil},
		{",,,", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		{" a , b ", []string{"a", "b"}},
		{"a,,b", []string{"a", "b"}},
		{"a,b,", []string{"a", "b"}},
	} {
		got := splitCSV(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("splitCSV(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("splitCSV(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	}
}

func TestEnvHelpersFallBackToTheirDefaults(t *testing.T) {
	const key = "OPENSHIELD_SERVER_TEST_VALUE"

	t.Run("env", func(t *testing.T) {
		t.Setenv(key, "")
		if got := env(key, "fallback"); got != "fallback" {
			t.Fatalf("env unset = %q", got)
		}
		t.Setenv(key, "set")
		if got := env(key, "fallback"); got != "set" {
			t.Fatalf("env set = %q", got)
		}
	})

	t.Run("envDuration", func(t *testing.T) {
		for _, tc := range []struct {
			val  string
			want time.Duration
		}{
			{"", time.Minute},
			{"30s", 30 * time.Second},
			{"2h", 2 * time.Hour},
			// A malformed duration falls back to the default rather than to zero: zero would usually mean
			// "no interval" or "no timeout", and neither is what a typo asked for.
			{"soon", time.Minute},
			{"30", time.Minute},
			{"-", time.Minute},
		} {
			t.Setenv(key, tc.val)
			if got := envDuration(key, time.Minute); got != tc.want {
				t.Fatalf("envDuration(%q) = %v, want %v", tc.val, got, tc.want)
			}
		}
	})

	// THIS envInt REQUIRES A POSITIVE VALUE, and it is not the same function as the agent's.
	//
	// cmd/openshield-agent has an envInt that accepts any integer; this one takes `n > 0` only, so 0 and
	// negatives fall back to the default. That is deliberate here — it sizes worker counts, batch sizes and
	// queue depths, where 0 is a misconfiguration rather than a choice — and it is worth pinning precisely
	// because the two share a name. I wrote this table against the agent's semantics first and the code
	// corrected me; a future reader comparing the two should find the difference asserted, not inferred.
	t.Run("envInt requires a positive value", func(t *testing.T) {
		for _, tc := range []struct {
			val  string
			want int
		}{
			{"", 5}, {"7", 7},
			{"0", 5},  // not a size
			{"-2", 5}, // nor is a negative one
			{"many", 5}, {"7.5", 5}, {"7s", 5},
		} {
			t.Setenv(key, tc.val)
			if got := envInt(key, 5); got != tc.want {
				t.Fatalf("envInt(%q) = %d, want %d", tc.val, got, tc.want)
			}
		}
	})
}
