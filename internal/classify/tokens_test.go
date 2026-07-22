package classify_test

import (
	"strings"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The API-token detector recognizes modern vendor prefixes (GitLab, npm, SendGrid, Stripe
// restricted, Twilio) in addition to GitHub/Slack/Google. Each is a distinctive prefix + a body
// length floor — a truncated or wrong-prefix look-alike must read clean.
func TestModernTokenPrefixes(t *testing.T) {
	a := func(n int) string { return strings.Repeat("a", n) }
	hex := func(n int) string { return strings.Repeat("f", n) }

	detected := []string{
		"GITLAB_TOKEN=glpat-" + a(20),
		"npm token npm_" + a(36),
		"SG." + a(22) + "." + a(43),
		"stripe rk_live_" + a(24),
		"twilio SK" + hex(32),
	}
	for _, s := range detected {
		if scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_API_TOKEN) == false {
			t.Errorf("token not detected in %q", s)
		}
	}

	benign := []string{
		"glpat_" + a(20),               // underscore, not the glpat- prefix
		"npm_" + a(10),                 // npm token body too short (needs 36)
		"SG." + a(22),                  // SendGrid missing the second segment
		"rk_test_" + a(24),             // restricted TEST key, not live (pattern is live only)
		"SK" + strings.Repeat("g", 32), // SK + non-hex → not a Twilio SID
	}
	for _, s := range benign {
		if scanFor2(t, s, corev1.DetectorType_DETECTOR_TYPE_API_TOKEN) {
			t.Errorf("false positive: token detected in %q", s)
		}
	}
}
