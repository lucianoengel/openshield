package main

import (
	"testing"
	"time"
)

// A FOURTH envInt lives here, and it is the permissive one. cmd/openshield-server's requires n > 0 because
// it sizes worker counts; this one and cmd/openshield-agent's accept any integer. Four functions sharing a
// name across one tree is a footgun, so each is pinned where it lives rather than left to be inferred from
// whichever the reader met first.
func TestEnvHelpers(t *testing.T) {
	const key = "OPENSHIELD_FLEET_AGENT_TEST"

	t.Run("env", func(t *testing.T) {
		t.Setenv(key, "")
		if got := env(key, "fallback"); got != "fallback" {
			t.Fatalf("env unset = %q", got)
		}
		t.Setenv(key, "v")
		if got := env(key, "fallback"); got != "v" {
			t.Fatalf("env set = %q", got)
		}
	})

	t.Run("envDuration", func(t *testing.T) {
		for _, tc := range []struct {
			val  string
			want time.Duration
		}{
			{"", 30 * time.Second},
			{"5s", 5 * time.Second},
			{"2m", 2 * time.Minute},
			// A malformed duration falls back rather than becoming zero: a zero heartbeat interval would
			// mean "publish continuously", which is not what a typo asked for.
			{"soon", 30 * time.Second},
			{"30", 30 * time.Second},
		} {
			t.Setenv(key, tc.val)
			if got := envDuration(key, 30*time.Second); got != tc.want {
				t.Fatalf("envDuration(%q) = %v, want %v", tc.val, got, tc.want)
			}
		}
	})

	t.Run("envInt accepts any integer here", func(t *testing.T) {
		for _, tc := range []struct {
			val  string
			want int
		}{
			{"", 3}, {"7", 7},
			{"0", 0}, // unlike cmd/openshield-server's, which requires n > 0
			{"-1", -1},
			{"lots", 3}, {"7.5", 3},
		} {
			t.Setenv(key, tc.val)
			if got := envInt(key, 3); got != tc.want {
				t.Fatalf("envInt(%q) = %d, want %d", tc.val, got, tc.want)
			}
		}
	})
}
