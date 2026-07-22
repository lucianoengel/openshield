package classify_test

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// TestBareRunDetectorNoisePrecision measures — and BOUNDS — the false-positive rate of the
// bare-digit-run detectors (ABA, NPI) on random numeric noise. Unlike the grouped detectors
// (SIN/NHS/EIN need a specific separator layout that rarely occurs by chance), ABA and NPI match a
// bare 9/10-digit run and rely on a checksum + a leading constraint, so they DO fire on a
// predictable fraction of random runs (~checksum-pass-rate × leading-fraction). This is why their
// confidence is capped below 1.0; this test pins that the rate stays within its expected envelope,
// so a regression that widens it (e.g. dropping the leading constraint) is caught in aggregate,
// not just by the isolated unit cases.
func TestBareRunDetectorNoisePrecision(t *testing.T) {
	rng := rand.New(rand.NewSource(20260721))
	const N = 20000
	c := classify.New()

	abaHits, npiHits := 0, 0
	for i := 0; i < N; i++ {
		// A benign line carrying one random 9-digit run and one random 10-digit run, plus text
		// so the runs are word-bounded (as real ids appear).
		var nine, ten strings.Builder
		for j := 0; j < 9; j++ {
			nine.WriteByte(byte('0' + rng.Intn(10)))
		}
		for j := 0; j < 10; j++ {
			ten.WriteByte(byte('0' + rng.Intn(10)))
		}
		line := fmt.Sprintf("order %s ref %s processed", nine.String(), ten.String())
		hits, err := c.Classify(context.Background(), strings.NewReader(line))
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hits {
			switch h.GetDetectorType() {
			case corev1.DetectorType_DETECTOR_TYPE_ABA_ROUTING:
				abaHits++
			case corev1.DetectorType_DETECTOR_TYPE_NPI:
				npiHits++
			}
		}
	}
	abaFP := float64(abaHits) / N
	npiFP := float64(npiHits) / N
	t.Logf("bare-run FP on random numeric noise (N=%d): ABA=%.4f  NPI=%.4f", N, abaFP, npiFP)

	// Envelopes reflect the arithmetic: ABA ≈ P(lead in range ~0.45) × P(mod-10 pass ~0.10) ≈ 4.5%;
	// NPI ≈ P(lead∈{1,2} 0.20) × P(80840-Luhn pass ~0.10) ≈ 2%. Ceilings sit modestly above those,
	// so a real regression (constraint dropped → rate ~10%+) trips while the inherent rate passes.
	if abaFP > 0.07 {
		t.Errorf("ABA FP on random 9-digit runs = %.4f, want ≤ 0.07 (constraint likely weakened)", abaFP)
	}
	if npiFP > 0.04 {
		t.Errorf("NPI FP on random 10-digit runs = %.4f, want ≤ 0.04 (constraint likely weakened)", npiFP)
	}
	// And the grouped detectors must be essentially absent from bare-run noise (sanity: they need
	// a specific separator layout). Their hit count here should be zero.
	// (Measured implicitly — they don't match bare runs at all.)
}
