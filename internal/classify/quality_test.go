package classify_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// --- corpus generators (self-contained; the recall assertion cross-checks that
// they agree with the real validators — a divergence would drop recall) ---

func cpfCheckDigit(s string, n int) byte {
	sum, weight := 0, n+1
	for i := 0; i < n; i++ {
		sum += int(s[i]-'0') * (weight - i)
	}
	r := (sum * 10) % 11
	if r == 10 {
		r = 0
	}
	return byte('0' + r)
}

// genCPF builds a genuinely valid 11-digit CPF (not all-same).
func genCPF(rng *rand.Rand) string {
	for {
		b := make([]byte, 11)
		for i := 0; i < 9; i++ {
			b[i] = byte('0' + rng.Intn(10))
		}
		b[9] = cpfCheckDigit(string(b[:9]), 9)
		b[10] = cpfCheckDigit(string(b[:10]), 10)
		allSame := true
		for i := 1; i < 11; i++ {
			if b[i] != b[0] {
				allSame = false
				break
			}
		}
		if !allSame {
			return string(b)
		}
	}
}

// nearMissCPF flips the last check digit so the checksum fails.
func nearMissCPF(rng *rand.Rand) string {
	v := []byte(genCPF(rng))
	v[10] = byte('0' + (int(v[10]-'0')+1)%10)
	return string(v)
}

func luhnValid(s string) bool {
	sum, double := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// genCard builds a 16-digit Luhn-valid number.
func genCard(rng *rand.Rand) string {
	b := make([]byte, 16)
	for i := 0; i < 15; i++ {
		b[i] = byte('0' + rng.Intn(10))
	}
	for c := 0; c < 10; c++ {
		b[15] = byte('0' + c)
		if luhnValid(string(b)) {
			return string(b)
		}
	}
	return string(b) // unreachable: exactly one c works
}

func nearMissCard(rng *rand.Rand) string {
	v := []byte(genCard(rng))
	v[15] = byte('0' + (int(v[15]-'0')+1)%10)
	return string(v)
}

// genSSNShaped builds a structurally-plausible SSN (area not 000/666/900+,
// group not 00, serial not 0000) — the detector has NO checksum, so these are the
// numbers it will over-flag.
func genSSNShaped(rng *rand.Rand) string {
	area := rng.Intn(898) + 1 // 1..898, skip 000/900+
	if area == 666 {
		area = 665
	}
	group := rng.Intn(99) + 1
	serial := rng.Intn(9999) + 1
	return fmt.Sprintf("%03d-%02d-%04d", area, group, serial)
}

func fired(t *testing.T, c *classify.Classifier, text string, dt corev1.DetectorType) bool {
	t.Helper()
	hits, err := c.Classify(context.Background(), strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if h.GetDetectorType() == dt {
			return true
		}
	}
	return false
}

// TestClassifierDetectionQuality measures precision/recall/FP against a labeled
// corpus including adversarial near-misses, and records the numbers. It asserts
// the checksum FP defense (CPF/card near-miss FP == 0), high recall on valid PII,
// and that the checksum-free SSN detector's FP materially exceeds the checksum
// detectors' — the measured reason its confidence is capped (D4/D5).
func TestClassifierDetectionQuality(t *testing.T) {
	rng := rand.New(rand.NewSource(20260721))
	c := classify.New()
	const N = 200

	// Positives: valid PII in realistic sentences.
	var cpfDetected, cardDetected int
	for i := 0; i < N; i++ {
		if fired(t, c, fmt.Sprintf("Cliente CPF %s aprovado em 2026.", genCPF(rng)), corev1.DetectorType_DETECTOR_TYPE_CPF) {
			cpfDetected++
		}
		if fired(t, c, fmt.Sprintf("Card on file ending %s, charged.", genCard(rng)), corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD) {
			cardDetected++
		}
	}
	cpfRecall := float64(cpfDetected) / N
	cardRecall := float64(cardDetected) / N

	// Negatives for the checksum detectors: near-misses + clean files. A failed
	// checksum must NEVER flag.
	clean := loadClean(t)
	var cpfFPs, cpfNeg, cardFPs, cardNeg int
	for i := 0; i < N; i++ {
		if fired(t, c, fmt.Sprintf("ref %s pending", nearMissCPF(rng)), corev1.DetectorType_DETECTOR_TYPE_CPF) {
			cpfFPs++
		}
		cpfNeg++
		if fired(t, c, fmt.Sprintf("token %s expired", nearMissCard(rng)), corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD) {
			cardFPs++
		}
		cardNeg++
	}
	for _, f := range clean {
		if fired(t, c, f, corev1.DetectorType_DETECTOR_TYPE_CPF) {
			cpfFPs++
		}
		cpfNeg++
		if fired(t, c, f, corev1.DetectorType_DETECTOR_TYPE_CREDIT_CARD) {
			cardFPs++
		}
		cardNeg++
	}
	cpfFP := float64(cpfFPs) / float64(cpfNeg)
	cardFP := float64(cardFPs) / float64(cardNeg)

	// The checksum-free SSN detector, on random SSN-shaped numbers.
	var ssnFPs int
	for i := 0; i < N; i++ {
		if fired(t, c, fmt.Sprintf("SSN %s on record", genSSNShaped(rng)), corev1.DetectorType_DETECTOR_TYPE_SSN) {
			ssnFPs++
		}
	}
	ssnFP := float64(ssnFPs) / N

	t.Logf("MEASURED detection quality (synthetic corpus, N=%d):", N)
	t.Logf("  CPF   recall=%.3f  near-miss+clean FP=%.3f", cpfRecall, cpfFP)
	t.Logf("  card  recall=%.3f  near-miss+clean FP=%.3f", cardRecall, cardFP)
	t.Logf("  SSN   (no checksum) FP on SSN-shaped=%.3f", ssnFP)

	// Assertions — floors/ceilings tied to the checksum property, not brittle counts.
	if cpfFP != 0 {
		t.Errorf("CPF FP on near-misses = %.3f, want 0 — a failed check digit flagged (checksum defense broken)", cpfFP)
	}
	if cardFP != 0 {
		t.Errorf("card FP on near-misses = %.3f, want 0 — a failed Luhn flagged", cardFP)
	}
	if cpfRecall < 0.98 {
		t.Errorf("CPF recall = %.3f, want ≥ 0.98 on generated-valid CPFs", cpfRecall)
	}
	if cardRecall < 0.98 {
		t.Errorf("card recall = %.3f, want ≥ 0.98 on Luhn-valid cards", cardRecall)
	}
	// The measured honesty point: the checksum-free detector over-flags, which is
	// exactly why its confidence is capped (D4/D5).
	if !(ssnFP > cpfFP) {
		t.Errorf("SSN FP (%.3f) is not greater than CPF FP (%.3f) — the checksum-free weakness should show", ssnFP, cpfFP)
	}
}

func loadClean(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("testdata", "clean")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	if len(out) == 0 {
		t.Fatal("no clean fixtures found")
	}
	return out
}
