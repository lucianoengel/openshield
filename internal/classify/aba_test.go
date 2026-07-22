package classify_test

import (
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// DLP: the ABA routing detector accepts real routing numbers (checksum + leading range) and
// rejects a random 9-digit run, a checksum-off-by-one, and a valid-checksum-but-bad-leading-range
// number — the two validators are both load-bearing.
func TestABARoutingDetector(t *testing.T) {
	// Real US routing numbers (verified checksums): Chase-NY, a bank on 01, Wells Fargo.
	for _, s := range []string{
		"wire to 021000021 today",
		"routing 011401533 account ...",
		"ABA: 121000248",
	} {
		if !scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_ABA_ROUTING) {
			t.Errorf("routing number not detected in %q", s)
		}
	}

	for _, s := range []string{
		"order 021000022 shipped",   // 021000021 + 1 → checksum fails
		"ticket 173000000 resolved", // lead 17 out of range (and structure off)
		"id 990000000 archived",     // checksum passes (sum 90) but lead 99 is out of range
		"code 123456789 ok",         // a plain sequential run: lead 12 in range but checksum fails
	} {
		if scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_ABA_ROUTING) {
			t.Errorf("false positive: routing number detected in %q", s)
		}
	}
}
