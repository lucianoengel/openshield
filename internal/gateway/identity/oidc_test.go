package identity_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway/identity"
)

// signJWT builds a compact-serialized JWT signed with the given alg+key. A helper so the
// test can forge tokens (valid and adversarial) without a live provider.
func signJWT(t *testing.T, alg, kid string, key crypto.PrivateKey, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	var sig []byte
	switch alg {
	case "EdDSA":
		sig = ed25519.Sign(key.(ed25519.PrivateKey), []byte(signing))
	case "RS256":
		sum := sha256.Sum256([]byte(signing))
		s, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = s
	default:
		t.Fatalf("unknown alg %q", alg)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// tamperSig flips one bit of a JWT's signature, yielding a guaranteed-invalid but
// well-formed token. It replaces an older "overwrite the last two base64 chars with
// AA" trick, which was a silent no-op whenever the signature's final byte already
// encoded to "AA" (~1/256 of Ed25519 keys) — the valid token then survived unchanged
// and was correctly accepted, making this fail-closed assertion flaky on CI.
func tamperSig(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-part JWT: %q", tok)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		t.Fatalf("decoding signature to tamper: %v", err)
	}
	sig[len(sig)-1] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

func baseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":    "https://issuer.example",
		"aud":    "openshield-gateway",
		"sub":    "alice@corp",
		"groups": []string{"finance"},
		"exp":    now.Add(time.Hour).Unix(),
		"nbf":    now.Add(-time.Minute).Unix(),
	}
}

func TestOIDCVerify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]crypto.PublicKey{"ed1": edPub, "rsa1": &rsaPriv.PublicKey}

	newV := func(t *testing.T) *identity.OIDCVerifier {
		v, err := identity.NewOIDCVerifier("https://issuer.example", "openshield-gateway", "groups", keys)
		if err != nil {
			t.Fatal(err)
		}
		return v.WithClock(func() time.Time { return now })
	}

	// Happy path, both algs: a valid token resolves to a pseudonymous subject + role.
	for _, tc := range []struct {
		alg, kid string
		key      crypto.PrivateKey
	}{{"EdDSA", "ed1", edPriv}, {"RS256", "rsa1", rsaPriv}} {
		tok := signJWT(t, tc.alg, tc.kid, tc.key, baseClaims(now))
		id, err := newV(t).Verify(tok)
		if err != nil {
			t.Fatalf("%s: valid token rejected: %v", tc.alg, err)
		}
		if id.Role != "finance" {
			t.Errorf("%s: role = %q, want finance", tc.alg, id.Role)
		}
		if id.Subject == "" || strings.Contains(id.Subject, "alice") {
			t.Errorf("%s: subject %q leaks the raw identity or is empty (must be a one-way pseudonym)", tc.alg, id.Subject)
		}
		if !strings.HasPrefix(id.Subject, "sub_") {
			t.Errorf("%s: subject %q is not a pseudonym", tc.alg, id.Subject)
		}
	}

	// Every adversarial token is REJECTED (fail-closed), each for its own reason.
	edKid, edKey := "ed1", edPriv
	bad := map[string]string{
		"tampered signature (EdDSA)": tamperSig(t, signJWT(t, "EdDSA", edKid, edKey, baseClaims(now))),
		"tampered signature (RS256)": tamperSig(t, signJWT(t, "RS256", "rsa1", rsaPriv, baseClaims(now))),
		"wrong issuer": func() string {
			c := baseClaims(now)
			c["iss"] = "https://evil.example"
			return signJWT(t, "EdDSA", edKid, edKey, c)
		}(),
		"wrong audience": func() string {
			c := baseClaims(now)
			c["aud"] = "some-other-app"
			return signJWT(t, "EdDSA", edKid, edKey, c)
		}(),
		"expired": func() string {
			c := baseClaims(now)
			c["exp"] = now.Add(-time.Hour).Unix()
			return signJWT(t, "EdDSA", edKid, edKey, c)
		}(),
		"not yet valid": func() string {
			c := baseClaims(now)
			c["nbf"] = now.Add(time.Hour).Unix()
			return signJWT(t, "EdDSA", edKid, edKey, c)
		}(),
		"unknown key id": func() string {
			return signJWT(t, "EdDSA", "unknown-kid", edKey, baseClaims(now))
		}(),
		"missing role claim": func() string {
			c := baseClaims(now)
			delete(c, "groups")
			return signJWT(t, "EdDSA", edKid, edKey, c)
		}(),
		"empty subject": func() string {
			c := baseClaims(now)
			c["sub"] = ""
			return signJWT(t, "EdDSA", edKid, edKey, c)
		}(),
		"alg none bypass": func() string {
			hdr, _ := json.Marshal(map[string]string{"alg": "none", "kid": edKid, "typ": "JWT"})
			pl, _ := json.Marshal(baseClaims(now))
			return base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl) + "."
		}(),
		"not a jwt": "garbage-token",
	}
	for name, tok := range bad {
		if _, err := newV(t).Verify(tok); err == nil {
			t.Errorf("adversarial token %q was ACCEPTED — the verifier must fail closed", name)
		}
	}
}

// A token signed by the RIGHT alg name but a key of the WRONG type (algorithm confusion:
// present an RSA-signed blob against the same kid mapped to an Ed25519 key) is rejected.
func TestOIDCAlgConfusion(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	// kid "k1" is an Ed25519 key, but the attacker signs RS256 and labels it "k1".
	keys := map[string]crypto.PublicKey{"k1": edPub}
	v, _ := identity.NewOIDCVerifier("https://issuer.example", "openshield-gateway", "groups", keys)
	v = v.WithClock(func() time.Time { return now })
	tok := signJWT(t, "RS256", "k1", rsaPriv, baseClaims(now))
	if _, err := v.Verify(tok); err == nil {
		t.Error("algorithm-confusion token accepted — RS256 verify must not run against an Ed25519 key")
	}
}

func TestNewOIDCVerifierConfig(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]crypto.PublicKey{"k": edPub}
	for _, tc := range []struct {
		iss, aud, role string
		keys           map[string]crypto.PublicKey
	}{
		{"", "aud", "groups", keys},
		{"iss", "", "groups", keys},
		{"iss", "aud", "", keys},
		{"iss", "aud", "groups", nil},
	} {
		if _, err := identity.NewOIDCVerifier(tc.iss, tc.aud, tc.role, tc.keys); err == nil {
			t.Errorf("NewOIDCVerifier(%q,%q,%q,keys=%d) did not error", tc.iss, tc.aud, tc.role, len(tc.keys))
		}
	}
}
