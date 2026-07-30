package main

import (
	"testing"
	"time"
)

// openshieldctl is the operator's read-only window onto the audit store — the tool D10 named as the
// replacement for an investigation UI — and it had NO TEST FILES AT ALL. 697 lines.
//
// Most of its surface needs a database, but its parsing does not, and parsing is where a CLI silently does
// the wrong thing: a flag that swallows the next flag as its value, a release artifact attributed to the
// wrong platform, an unknown flag accepted and ignored.

// platformOf turns a release artifact name into the platform it was built for, and that string ends up in
// the release manifest that verifyRelease checks. Getting it wrong does not fail loudly — it produces a
// manifest that disagrees with reality about which binary runs where.
func TestPlatformOfParsesArtifactNames(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"openshield-agent_linux_amd64", "linux/amd64"},
		{"openshield-agent_linux_arm64", "linux/arm64"},
		{"openshield-gateway_darwin_arm64", "darwin/arm64"},
		{"openshield-agent_windows_amd64.exe", "windows/amd64"},
		// A binary name containing underscores must still resolve by its LAST two components.
		{"openshield_fleet_agent_linux_amd64", "linux/amd64"},

		// Too few components to name a platform: empty, not a guess.
		{"openshield-agent", ""},
		{"agent_linux", ""},
		{"", ""},
		{".exe", ""},
	} {
		t.Run("name="+tc.name, func(t *testing.T) {
			if got := platformOf(tc.name); got != tc.want {
				t.Fatalf("platformOf(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestParseBackupFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want map[string]string
	}{
		{"empty", nil, map[string]string{}},
		{"one pair", []string{"--out", "/tmp/b"}, map[string]string{"out": "/tmp/b"}},
		{"several", []string{"--out", "/tmp/b", "--dsn", "postgres://x"},
			map[string]string{"out": "/tmp/b", "dsn": "postgres://x"}},
		// A bare flag records presence as "", and must NOT consume the flag that follows it.
		{"bare flag", []string{"--print"}, map[string]string{"print": ""}},
		{"bare flag before another", []string{"--print", "--out", "/tmp/b"},
			map[string]string{"print": "", "out": "/tmp/b"}},
		{"bare flag last", []string{"--out", "/tmp/b", "--print"},
			map[string]string{"out": "/tmp/b", "print": ""}},
		{"stray positional is ignored", []string{"junk", "--out", "/tmp/b"},
			map[string]string{"out": "/tmp/b"}},
		{"a later value wins", []string{"--out", "/a", "--out", "/b"}, map[string]string{"out": "/b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseBackupFlags(tc.args)
			if len(got) != len(tc.want) {
				t.Fatalf("parseBackupFlags(%q) = %v, want %v", tc.args, got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("parseBackupFlags(%q)[%q] = %q, want %q", tc.args, k, got[k], v)
				}
			}
		})
	}
}

// valueOr treats an EMPTY value as absent, which is what makes `--out` with no argument fall back to the
// default rather than writing to "".
func TestValueOrTreatsEmptyAsAbsent(t *testing.T) {
	f := map[string]string{"set": "value", "bare": ""}
	for _, tc := range []struct{ key, fallback, want string }{
		{"set", "fb", "value"},
		{"bare", "fb", "fb"},
		{"missing", "fb", "fb"},
		{"set", "", "value"},
	} {
		if got := valueOr(f, tc.key, tc.fallback); got != tc.want {
			t.Fatalf("valueOr(%q, %q) = %q, want %q", tc.key, tc.fallback, got, tc.want)
		}
	}
}

func TestParseSubjectSplitsTheAnchorVerb(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cmd      string
		args     []string
		wantVerb string
		wantRest []string
	}{
		{"anchor with a verb", "anchor", []string{"export", "--anchor", "/tmp/a"}, "export", []string{"--anchor", "/tmp/a"}},
		{"anchor with only a verb", "anchor", []string{"export"}, "export", []string{}},
		{"anchor with no args", "anchor", nil, "", nil},
		{"another command keeps all args", "timeline", []string{"--subject", "s"}, "", []string{"--subject", "s"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSubject(tc.cmd, tc.args)
			if got.verb != tc.wantVerb {
				t.Fatalf("verb = %q, want %q", got.verb, tc.wantVerb)
			}
			if len(got.rest) != len(tc.wantRest) {
				t.Fatalf("rest = %v, want %v", got.rest, tc.wantRest)
			}
			for i := range tc.wantRest {
				if got.rest[i] != tc.wantRest[i] {
					t.Fatalf("rest = %v, want %v", got.rest, tc.wantRest)
				}
			}
		})
	}
}

func TestFlagsParse(t *testing.T) {
	t.Run("every flag round trips", func(t *testing.T) {
		f := &flags{}
		err := f.parse([]string{
			"--dsn", "postgres://h/db",
			"--subject", "sub_abc",
			"--event", "evt-1",
			"--anchor", "/tmp/anchor.pem",
			"--witness", "/tmp/witness.pub",
			"--since", "2026-01-02T15:04:05Z",
			"--until", "2026-01-03T15:04:05Z",
		})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if f.dsn != "postgres://h/db" || f.subject != "sub_abc" || f.event != "evt-1" ||
			f.anchor != "/tmp/anchor.pem" || f.witness != "/tmp/witness.pub" {
			t.Fatalf("string flags did not round trip: %+v", f)
		}
		if !f.since.Equal(time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)) {
			t.Fatalf("--since = %v", f.since)
		}
		if !f.until.Equal(time.Date(2026, 1, 3, 15, 4, 5, 0, time.UTC)) {
			t.Fatalf("--until = %v", f.until)
		}
	})

	// AN UNKNOWN FLAG IS AN ERROR. Silently ignoring one means `--subjekt sub_abc` runs the query against
	// every subject and prints a confident answer to a question the operator did not ask.
	t.Run("rejections", func(t *testing.T) {
		for name, args := range map[string][]string{
			"unknown flag":            {"--subjekt", "sub_abc"},
			"a value with no flag":    {"sub_abc"},
			"flag missing its value":  {"--subject"},
			"trailing flag no value":  {"--dsn", "x", "--subject"},
			"unparseable since":       {"--since", "yesterday"},
			"unparseable until":       {"--until", "2026-13-45"},
			"since without a zone":    {"--since", "2026-01-02 15:04:05"},
		} {
			t.Run(name, func(t *testing.T) {
				if err := (&flags{}).parse(args); err == nil {
					t.Fatalf("parse(%q) accepted an invalid invocation", args)
				}
			})
		}
	})

	// A flag must not swallow the NEXT flag as its value — that would set --subject to "--event" and then
	// silently drop the real event id.
	//
	// Written carelessly the first time: I parsed into one flags value and asserted against a DIFFERENT,
	// untouched one, so f.subject was always "" and the assertion could never fire. It is the same vacuous
	// shape this project keeps finding — a check that passes because it is looking at the wrong object.
	t.Run("a flag does not consume the next flag", func(t *testing.T) {
		f := &flags{}
		err := f.parse([]string{"--subject", "--event"})
		if f.subject == "--event" {
			t.Fatal("--subject swallowed the following flag as its value, and the real --event was dropped")
		}
		if err == nil && f.subject == "" {
			t.Fatal("parse accepted `--subject --event` and set nothing, silently ignoring both")
		}
	})
}
