package identity_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway/identity"
)

// ed25519Thumbprint computes the RFC 7638/8037 thumbprint of an Ed25519 public key — the value that
// goes in the access token's cnf.jkt and that the verifier recomputes from the proof's embedded JWK.
func ed25519Thumbprint(pub ed25519.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub)
	canon := `{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// signDPoP mints a DPoP proof JWT bound to method+htu, signed by the given Ed25519 key, embedding its
// public JWK in the header. jti and iat let a test drive replay/freshness.
func signDPoP(t *testing.T, priv ed25519.PrivateKey, method, htu, jti string, iat time.Time) string {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	jwk := map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
	hdr, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk})
	pl, _ := json.Marshal(map[string]any{"htm": method, "htu": htu, "iat": iat.Unix(), "jti": jti})
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	sig := ed25519.Sign(priv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestDPoPSenderConstraint (R34-10): a token carrying cnf.jkt is accepted ONLY with a valid DPoP proof
// from the bound key + right request; a stolen token replayed without the key (or with a mismatched
// proof) is refused. This is the fix for "any enrolled device replays another user's token".
func TestDPoPSenderConstraint(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader) // token-signing key (the IdP)
	keys := map[string]crypto.PublicKey{"ed1": edPub}

	// The client's DPoP key — its thumbprint binds the token.
	dpopPub, dpopPriv, _ := ed25519.GenerateKey(rand.Reader)
	jkt := ed25519Thumbprint(dpopPub)

	newV := func() *identity.OIDCVerifier {
		v, err := identity.NewOIDCVerifier("https://issuer.example", "openshield-gateway", "groups", keys)
		if err != nil {
			t.Fatal(err)
		}
		return v.WithClock(func() time.Time { return now }).EnableDPoP(1024)
	}

	claims := baseClaims(now)
	claims["cnf"] = map[string]string{"jkt": jkt}
	tok := signJWT(t, "EdDSA", "ed1", edPriv, claims)

	const method, htu = "GET", "https://gw.example/api/data"

	// A valid proof from the bound key → accepted.
	proof := signDPoP(t, dpopPriv, method, htu, "jti-1", now)
	if _, err := newV().VerifyWithProof(tok, proof, method, htu); err != nil {
		t.Fatalf("a valid DPoP-bound request was rejected: %v", err)
	}

	// The stolen token WITHOUT a proof → refused (the core replay defense).
	if _, err := newV().VerifyWithProof(tok, "", method, htu); err == nil {
		t.Fatal("a sender-constrained token was accepted with NO DPoP proof — replay not prevented")
	}

	// A proof from a DIFFERENT (attacker) key → refused (thumbprint mismatch).
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	badKeyProof := signDPoP(t, otherPriv, method, htu, "jti-2", now)
	if _, err := newV().VerifyWithProof(tok, badKeyProof, method, htu); err == nil {
		t.Fatal("a DPoP proof under a non-bound key was accepted — cnf.jkt not enforced")
	}

	// A proof bound to a DIFFERENT method/URL → refused (can't lift a proof onto another request).
	wrongReq := signDPoP(t, dpopPriv, "POST", "https://gw.example/api/other", "jti-3", now)
	if _, err := newV().VerifyWithProof(tok, wrongReq, method, htu); err == nil {
		t.Fatal("a DPoP proof for a different method/URI was accepted — htm/htu not enforced")
	}

	// A stale proof (iat far in the past) → refused.
	stale := signDPoP(t, dpopPriv, method, htu, "jti-4", now.Add(-10*time.Minute))
	if _, err := newV().VerifyWithProof(tok, stale, method, htu); err == nil {
		t.Fatal("a stale DPoP proof was accepted — freshness window not enforced")
	}
}

// TestDPoPProofSingleUse (R34-10): a captured, still-fresh, otherwise-valid proof cannot be replayed —
// the jti is single-use per verifier.
func TestDPoPProofSingleUse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]crypto.PublicKey{"ed1": edPub}
	dpopPub, dpopPriv, _ := ed25519.GenerateKey(rand.Reader)

	v, err := identity.NewOIDCVerifier("https://issuer.example", "openshield-gateway", "groups", keys)
	if err != nil {
		t.Fatal(err)
	}
	v = v.WithClock(func() time.Time { return now }).EnableDPoP(1024)

	claims := baseClaims(now)
	claims["cnf"] = map[string]string{"jkt": ed25519Thumbprint(dpopPub)}
	tok := signJWT(t, "EdDSA", "ed1", edPriv, claims)

	const method, htu = "GET", "https://gw.example/api/data"
	proof := signDPoP(t, dpopPriv, method, htu, "reused-jti", now)

	if _, err := v.VerifyWithProof(tok, proof, method, htu); err != nil {
		t.Fatalf("first use of a valid proof rejected: %v", err)
	}
	if _, err := v.VerifyWithProof(tok, proof, method, htu); err == nil {
		t.Fatal("the SAME DPoP proof was accepted twice — jti replay not prevented")
	}
}

// TestOIDCClockSkewLeeway (R34-10): a token that expired just now (within the leeway) is still
// accepted, and one that became valid just now (nbf slightly in the future) too — sub-minute drift
// must not spuriously reject a valid token. Well past the leeway it IS rejected.
func TestOIDCClockSkewLeeway(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]crypto.PublicKey{"ed1": edPub}
	newV := func() *identity.OIDCVerifier {
		v, _ := identity.NewOIDCVerifier("https://issuer.example", "openshield-gateway", "groups", keys)
		return v.WithClock(func() time.Time { return now }).WithLeeway(30 * time.Second)
	}

	// exp 10s in the PAST — within a 30s leeway, still accepted.
	c := baseClaims(now)
	c["exp"] = now.Add(-10 * time.Second).Unix()
	if _, err := newV().Verify(signJWT(t, "EdDSA", "ed1", edPriv, c)); err != nil {
		t.Errorf("a token expired 10s ago was rejected despite a 30s leeway: %v", err)
	}

	// exp 60s in the past — beyond the leeway, rejected.
	c2 := baseClaims(now)
	c2["exp"] = now.Add(-60 * time.Second).Unix()
	if _, err := newV().Verify(signJWT(t, "EdDSA", "ed1", edPriv, c2)); err == nil {
		t.Error("a token expired 60s ago was accepted with only a 30s leeway")
	}

	// nbf 10s in the FUTURE — within the leeway, accepted.
	c3 := baseClaims(now)
	c3["nbf"] = now.Add(10 * time.Second).Unix()
	if _, err := newV().Verify(signJWT(t, "EdDSA", "ed1", edPriv, c3)); err != nil {
		t.Errorf("a token not-yet-valid by 10s was rejected despite a 30s leeway: %v", err)
	}
}
