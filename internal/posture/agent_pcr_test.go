package posture_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/posture"
)

// TestAnUnparseablePCREntryIsSkippedButAnnounced.
//
// MOVED HERE FROM cmd/openshield-fleet-agent (CONSOLE-8e) with the code it covers. It was a test of the
// simulator; the property belongs to every agent that attests.
//
// The failure it guards is not a parsing nicety. `OPENSHIELD_ATTEST_PCRS=0,seven` yields [0]: the agent
// enrols a baseline over PCR 0 alone while the operator asked for two. Downstream validation cannot catch
// it, because [0] is a perfectly valid non-empty baseline. The attestation is narrower than requested and
// nothing says so — which is the failure D31 names.
//
// Mutation: drop the warning branch from ParsePCRs → the "announced" half FAILS.
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
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, nil))
			got := posture.ParsePCRs(tc.in, log)

			if len(got) != len(tc.want) {
				t.Fatalf("ParsePCRs(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("ParsePCRs(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}

			logged := buf.String()
			if len(tc.skipped) == 0 {
				if strings.Contains(logged, "unparseable") {
					t.Fatalf("ParsePCRs(%q) warned about nothing:\n%s", tc.in, logged)
				}
				return
			}
			for _, s := range tc.skipped {
				if !strings.Contains(logged, s) {
					t.Fatalf("ParsePCRs(%q) dropped %q without naming it; the baseline is now narrower "+
						"than the operator asked for and nothing says so:\n%s", tc.in, s, logged)
				}
			}
		})
	}
}

// TestParsePCRsToleratesNoLogger — the orchestration passes a logger, but a caller that has none must not
// panic on a typo. A nil-logger crash would turn a configuration mistake into a dead agent.
func TestParsePCRsToleratesNoLogger(t *testing.T) {
	if got := posture.ParsePCRs("0,seven", nil); len(got) != 1 || got[0] != 0 {
		t.Fatalf("ParsePCRs with no logger = %v, want [0]", got)
	}
}
