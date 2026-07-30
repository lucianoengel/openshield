package identity_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway/identity"
)

// THE OPERATOR PATH MUST NOT BE THE WEAK ONE.
//
// VerifySubject is what authenticates a human operator; Verify is what authenticates a ZTNA client. They
// share verifyCore precisely so a check cannot go missing from one of them, and oidc.go says so: "a second
// copy of JWT validation is a second place for a check to go missing."
//
// That is a claim about the code's structure, and structure is not self-enforcing — someone can add a
// shortcut to VerifySubject in a future change without touching Verify's tests. So every adversarial token
// the ZTNA path rejects is fed to the OPERATOR path here too. Both entry points were at 0% coverage.

func operatorTestVerifier(t *testing.T, keys map[string]crypto.PublicKey, now time.Time) *identity.OIDCVerifier {
	t.Helper()
	v, err := identity.NewOperatorVerifierWithSource("https://issuer.example", "openshield-gateway",
		func(kid string) (crypto.PublicKey, bool) { k, ok := keys[kid]; return k, ok })
	if err != nil {
		t.Fatal(err)
	}
	return v.WithClock(func() time.Time { return now })
}

func TestVerifySubjectAcceptsAValidOperatorToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]crypto.PublicKey{"ed1": pub}

	tok := signJWT(t, "EdDSA", "ed1", priv, baseClaims(now))
	sub, err := operatorTestVerifier(t, keys, now).VerifySubject(tok)
	if err != nil {
		t.Fatalf("a valid operator token was rejected: %v", err)
	}
	// VerifySubject returns the RAW subject claim, unlike Verify which pseudonymises. That is deliberate:
	// the control plane keys operator roles on the identity the provider asserts. Asserted so a future
	// change cannot silently swap one for the other and leave every role lookup missing.
	if sub != "alice@corp" {
		t.Fatalf("VerifySubject returned %q, want the raw subject claim alice@corp", sub)
	}
}

func TestVerifySubjectRejectsEverythingTheZTNAPathRejects(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]crypto.PublicKey{"ed1": pub}

	claimsWith := func(mut func(map[string]any)) map[string]any {
		c := baseClaims(now)
		mut(c)
		return c
	}

	for name, tok := range map[string]string{
		"tampered signature":                      tamperSig(t, signJWT(t, "EdDSA", "ed1", priv, baseClaims(now))),
		"signed by an unknown key":                signJWT(t, "EdDSA", "unknown-kid", otherPriv, baseClaims(now)),
		"signed by the wrong key for a known kid": signJWT(t, "EdDSA", "ed1", otherPriv, baseClaims(now)),
		"wrong issuer": signJWT(t, "EdDSA", "ed1", priv, claimsWith(func(c map[string]any) {
			c["iss"] = "https://evil.example"
		})),
		"wrong audience": signJWT(t, "EdDSA", "ed1", priv, claimsWith(func(c map[string]any) {
			c["aud"] = "someone-else"
		})),
		"expired": signJWT(t, "EdDSA", "ed1", priv, claimsWith(func(c map[string]any) {
			c["exp"] = now.Add(-time.Hour).Unix()
		})),
		"not yet valid": signJWT(t, "EdDSA", "ed1", priv, claimsWith(func(c map[string]any) {
			c["nbf"] = now.Add(time.Hour).Unix()
		})),
		"no subject": signJWT(t, "EdDSA", "ed1", priv, claimsWith(func(c map[string]any) {
			delete(c, "sub")
		})),
		"empty subject": signJWT(t, "EdDSA", "ed1", priv, claimsWith(func(c map[string]any) {
			c["sub"] = ""
		})),
		"not a JWT at all":    "definitely-not-a-token",
		"two segments":        "aaa.bbb",
		"empty":               "",
		"unsigned (alg none)": "eyJhbGciOiJub25lIiwia2lkIjoiZWQxIn0.eyJzdWIiOiJhbGljZUBjb3JwIn0.",
	} {
		t.Run(name, func(t *testing.T) {
			sub, err := operatorTestVerifier(t, keys, now).VerifySubject(tok)
			if err == nil {
				t.Fatalf("the operator path ACCEPTED %s and returned subject %q — this token is refused on "+
					"the ZTNA path, so the two have drifted", name, sub)
			}
			if sub != "" {
				t.Fatalf("rejected %s but still returned subject %q; a caller checking the subject before "+
					"the error would authenticate them", name, sub)
			}
		})
	}
}

func TestVerifierConstructorsRefuseAnUnusableConfiguration(t *testing.T) {
	ks := func(string) (crypto.PublicKey, bool) { return nil, false }

	t.Run("ztna", func(t *testing.T) {
		for name, tc := range map[string]struct {
			issuer, audience, roleClaim string
			keyFor                      func(string) (crypto.PublicKey, bool)
		}{
			"no issuer":     {"", "aud", "groups", ks},
			"no audience":   {"iss", "", "groups", ks},
			"no role claim": {"iss", "aud", "", ks},
			"no key source": {"iss", "aud", "groups", nil},
		} {
			t.Run(name, func(t *testing.T) {
				v, err := identity.NewOIDCVerifierWithSource(tc.issuer, tc.audience, tc.roleClaim, tc.keyFor)
				if err == nil {
					t.Fatalf("built a verifier with %s — it would fail at request time, on the request", name)
				}
				if v != nil {
					t.Fatal("returned a non-nil verifier alongside the error")
				}
			})
		}
		if _, err := identity.NewOIDCVerifierWithSource("iss", "aud", "groups", ks); err != nil {
			t.Fatalf("a complete configuration was refused: %v", err)
		}
	})

	t.Run("operator", func(t *testing.T) {
		// No role claim here: operator roles come from the control plane's own table, not the token (D379).
		for name, tc := range map[string]struct {
			issuer, audience string
			keyFor           func(string) (crypto.PublicKey, bool)
		}{
			"no issuer":     {"", "aud", ks},
			"no audience":   {"iss", "", ks},
			"no key source": {"iss", "aud", nil},
		} {
			t.Run(name, func(t *testing.T) {
				v, err := identity.NewOperatorVerifierWithSource(tc.issuer, tc.audience, tc.keyFor)
				if err == nil {
					t.Fatalf("built an operator verifier with %s", name)
				}
				if v != nil {
					t.Fatal("returned a non-nil verifier alongside the error")
				}
			})
		}
		if _, err := identity.NewOperatorVerifierWithSource("iss", "aud", ks); err != nil {
			t.Fatalf("a complete configuration was refused: %v", err)
		}
	})
}

// A key source that starts empty and fills in later is the JWKS-refresher case. The verifier must consult
// it on EVERY verification rather than caching a miss, or the first token to arrive before the first
// refresh would poison every later one.
func TestTheKeySourceIsConsultedOnEveryVerification(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	var available bool
	v, err := identity.NewOperatorVerifierWithSource("https://issuer.example", "openshield-gateway",
		func(kid string) (crypto.PublicKey, bool) {
			if !available || kid != "ed1" {
				return nil, false
			}
			return pub, true
		})
	if err != nil {
		t.Fatal(err)
	}
	v = v.WithClock(func() time.Time { return now })

	tok := signJWT(t, "EdDSA", "ed1", priv, baseClaims(now))
	if _, err := v.VerifySubject(tok); err == nil {
		t.Fatal("a token was accepted before its key was known")
	} else if !strings.Contains(err.Error(), "unknown key id") {
		t.Fatalf("unexpected error before the key arrived: %v", err)
	}

	available = true // the refresher has now fetched the IdP's keys
	if _, err := v.VerifySubject(tok); err != nil {
		t.Fatalf("the same token was still rejected after its key became available — a miss was cached, "+
			"so an IdP key rotation would need a restart: %v", err)
	}
}
