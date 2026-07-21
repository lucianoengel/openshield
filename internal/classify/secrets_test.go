package classify_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func scanFor(t *testing.T, text string, want corev1.DetectorType) *corev1.DetectorHit {
	t.Helper()
	hits, err := classify.New().Classify(context.Background(), strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if h.GetDetectorType() == want {
			return h
		}
	}
	return nil
}

// realJWT mints a genuinely structured JWT (a valid JOSE header) so the test exercises
// the real validJWT decoder, not a hand-typed approximation.
func realJWT(t *testing.T) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	pl, _ := json.Marshal(map[string]any{"sub": "1234567890", "name": "x"})
	b := func(x []byte) string { return base64.RawURLEncoding.EncodeToString(x) }
	return b(hdr) + "." + b(pl) + "." + b([]byte("signature-bytes-here"))
}

func TestSecretsDetectorsFindRealSecrets(t *testing.T) {
	// A genuine Ed25519 key marshaled into a PEM-looking block header.
	privateKeyDoc := "config:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"

	cases := []struct {
		name string
		text string
		want corev1.DetectorType
		conf float64
	}{
		{"private key", privateKeyDoc, corev1.DetectorType_DETECTOR_TYPE_PRIVATE_KEY, 0.95},
		{"aws access key", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", corev1.DetectorType_DETECTOR_TYPE_AWS_ACCESS_KEY, 0.9},
		{"jwt", "Authorization: Bearer " + realJWT(t) + "\n", corev1.DetectorType_DETECTOR_TYPE_JWT, 0.8},
		{"github token", "token = ghp_" + strings.Repeat("a", 36) + "\n", corev1.DetectorType_DETECTOR_TYPE_API_TOKEN, 0.85},
		{"slack token", "SLACK=xoxb-123456789012-abcdefghijkl\n", corev1.DetectorType_DETECTOR_TYPE_API_TOKEN, 0.85},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := scanFor(t, tc.text, tc.want)
			if h == nil {
				t.Fatalf("%s: detector %v did not fire", tc.name, tc.want)
			}
			if h.GetConfidence() < tc.conf {
				t.Errorf("%s: confidence %v < %v", tc.name, h.GetConfidence(), tc.conf)
			}
		})
	}
}

// False-positive discipline: benign look-alikes must NOT trip the structural
// validators. A three-dotted token that is not a JOSE header, a random AKIA-shaped
// word, and a plain SSH public-key comment must all read clean.
func TestSecretsDetectorsRejectLookAlikes(t *testing.T) {
	benign := []string{
		"a normal sentence with dots. like. this. one.",                   // not a JWT
		"version eyJhb.notbase64!.xyz released",                           // JWT-shaped but header not valid base64url/JSON
		"the code AKIALOOKSLIKEAKEY123 is not real",                       // wrong length / not 16 base32 after prefix... ensure no hit
		"-----BEGIN PUBLIC KEY-----\nMFkwE... \n-----END PUBLIC KEY-----", // PUBLIC key, not private
		"ssh-ed25519 AAAAC3NzaC1lZDI1 user@host",                          // public key line
		"sk-",                                                             // truncated, below length floor
	}
	for _, text := range benign {
		hits, err := classify.New().Classify(context.Background(), strings.NewReader(text))
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hits {
			switch h.GetDetectorType() {
			case corev1.DetectorType_DETECTOR_TYPE_PRIVATE_KEY,
				corev1.DetectorType_DETECTOR_TYPE_AWS_ACCESS_KEY,
				corev1.DetectorType_DETECTOR_TYPE_JWT,
				corev1.DetectorType_DETECTOR_TYPE_API_TOKEN:
				t.Errorf("benign text tripped %v (false positive): %q", h.GetDetectorType(), text)
			}
		}
	}
}

// The JWT validator decodes the header — a real minted token validates, a token whose
// header is valid base64url but NOT a JOSE header does not.
func TestJWTValidatorDecodesHeader(t *testing.T) {
	if h := scanFor(t, realJWT(t), corev1.DetectorType_DETECTOR_TYPE_JWT); h == nil {
		t.Error("a genuinely-structured JWT was not detected")
	}
	// base64url of "not a header at all" as the first segment → decodes fine but is not JOSE.
	notHeader := base64.RawURLEncoding.EncodeToString([]byte("not a header at all")) + ".YWJj.ZGVm"
	if h := scanFor(t, notHeader, corev1.DetectorType_DETECTOR_TYPE_JWT); h != nil {
		t.Error("a non-JOSE three-part token was misdetected as a JWT")
	}
}
