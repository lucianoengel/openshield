package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// capturingStderr runs fn with os.Stderr replaced by a pipe and returns what it wrote.
func capturingStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()

	fn()

	os.Stderr = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// THE THIRD PCR PARSER IN THIS TREE, and it does not agree with the others.
//
// openshield-provision's parsePCRList REFUSES a malformed index, on the stated grounds that an empty
// baseline "attests to nothing". This one skips and carries on, which is the right call for a simulation
// agent that should not die on a typo — but it used to skip SILENTLY, and that is a different thing.
//
// `OPENSHIELD_ATTEST_PCRS=0,seven` yields [0]: the agent enrols a baseline over PCR 0 alone while the
// operator asked for two. Downstream validation cannot catch it, because [0] is a valid non-empty
// baseline. The attestation is narrower than requested and nothing says so — which is the failure D31
// names, not a parsing nicety.
func TestAnUnparseablePCREntryIsSkippedButAnnounced(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    []int
		skipped []string
	}{
		{"0,7", []int{0, 7}, nil},
		{" 0 , 7 ", []int{0, 7}, nil},
		{"0,,7", []int{0, 7}, nil},
		{"", nil, nil},
		{"   ", nil, nil},

		{"0,seven", []int{0}, []string{"seven"}},
		{"zero,7", []int{7}, []string{"zero"}},
		{"0,7,0x10", []int{0, 7}, []string{"0x10"}},
		{"all", nil, []string{"all"}},
	} {
		t.Run("value="+tc.in, func(t *testing.T) {
			var got []int
			stderr := capturingStderr(t, func() { got = parsePCRs(tc.in) })

			if len(got) != len(tc.want) {
				t.Fatalf("parsePCRs(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("parsePCRs(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}

			if len(tc.skipped) == 0 {
				if strings.Contains(stderr, "ignoring") {
					t.Fatalf("parsePCRs(%q) warned about nothing:\n%s", tc.in, stderr)
				}
				return
			}
			for _, s := range tc.skipped {
				if !strings.Contains(stderr, s) {
					t.Fatalf("parsePCRs(%q) dropped %q without naming it; the baseline is now narrower "+
						"than the operator asked for and nothing says so:\n%s", tc.in, s, stderr)
				}
			}
		})
	}
}

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
			{"0", 0},  // unlike cmd/openshield-server's, which requires n > 0
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
