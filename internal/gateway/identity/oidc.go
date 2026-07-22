package identity

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OIDCVerifier resolves a signed OIDC/JWT bearer token into an Identity (A.2b): the
// SECOND identity producer beside the client certificate (D86). Where the client cert
// is a device/mTLS credential, an OIDC token is a federated HUMAN credential — a
// deployment that authenticates users through an SSO provider (Okta, Entra, Keycloak)
// gets verified identity from the token instead of issuing a client cert per user.
//
// It is the PRODUCER only. Composing a user token WITH a device cert (BeyondCorp's two
// credentials — user identity from the token, device identity + posture from the cert)
// is a deliberate follow-up: the access proxy currently authenticates by one credential,
// and dual-credential composition is a deployment design choice, staged after this
// producer exactly as the client-cert producer (D86) preceded its access wiring (D87).
//
// This verifier does OFFLINE token validation against a STATIC key set: issuer,
// audience, expiry/not-before, and signature. Live discovery + JWKS rotation (fetching
// the provider's keys over HTTP) is a follow-up — and deliberately so: the gateway is
// the master chokepoint (D74), so an outbound fetch on the auth path is a dependency to
// add consciously, not by default. The operator configures the trusted keys.
type OIDCVerifier struct {
	issuer    string
	audience  string
	roleClaim string
	// keyFor resolves a key id to its public key. A static verifier closes over a fixed map; a
	// JWKS-backed verifier (ZT-2b) reads a background-refreshed snapshot. Verify NEVER fetches — the
	// key SOURCE is the only thing that varies, the verification logic is unchanged.
	keyFor func(kid string) (crypto.PublicKey, bool)
	now    func() time.Time // injectable clock (testability, D28-style)
	// leeway is the allowed clock skew between the gateway and the IdP when checking exp/nbf
	// (R34-10): without it a token is spuriously rejected (or briefly over-accepted) by sub-second
	// clock drift. Bounded small so it never materially extends a token's life.
	leeway time.Duration
	// dpopReplay records recently-seen DPoP proof jtis so a captured proof cannot be replayed
	// (R34-10); nil until sender-constraining is turned on. The ACCESS token stays reusable
	// per-request (correct for a bearer access token) — it is the per-request DPoP PROOF that is
	// single-use, which is what actually stops cross-device replay.
	dpopReplay *seenSet
}

// NewOIDCVerifier builds a verifier. issuer and audience are REQUIRED — a token whose
// `iss`/`aud` do not match is rejected, so a token minted for another relying party (or
// by another provider) can never authorize here. roleClaim names the claim carrying the
// authorization group (e.g. "groups" or a custom "role"); keys maps each key id (`kid`)
// to its public key. An empty issuer, audience, roleClaim, or key set is a configuration
// error — a verifier that trusts everything is never constructed.
func NewOIDCVerifier(issuer, audience, roleClaim string, keys map[string]crypto.PublicKey) (*OIDCVerifier, error) {
	if issuer == "" || audience == "" || roleClaim == "" {
		return nil, fmt.Errorf("identity: OIDC verifier needs issuer, audience, and role claim")
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("identity: OIDC verifier needs at least one signing key")
	}
	static := make(map[string]crypto.PublicKey, len(keys))
	for k, v := range keys {
		static[k] = v
	}
	return &OIDCVerifier{issuer: issuer, audience: audience, roleClaim: roleClaim,
		keyFor: func(kid string) (crypto.PublicKey, bool) { k, ok := static[kid]; return k, ok },
		now:    time.Now}, nil
}

// NewOIDCVerifierWithSource builds a verifier whose signing keys come from an external source (e.g. a
// live JWKS refresher, ZT-2b) rather than a static map — for a provider whose keys rotate. The source's
// keyFor MUST NOT block on the network (the verify path is HTTP-free). issuer/audience/roleClaim are
// required exactly as in NewOIDCVerifier; a nil source is a configuration error.
func NewOIDCVerifierWithSource(issuer, audience, roleClaim string, keyFor func(kid string) (crypto.PublicKey, bool)) (*OIDCVerifier, error) {
	if issuer == "" || audience == "" || roleClaim == "" {
		return nil, fmt.Errorf("identity: OIDC verifier needs issuer, audience, and role claim")
	}
	if keyFor == nil {
		return nil, fmt.Errorf("identity: OIDC verifier needs a key source")
	}
	return &OIDCVerifier{issuer: issuer, audience: audience, roleClaim: roleClaim, keyFor: keyFor, now: time.Now}, nil
}

// SetKeySource routes key lookup through an external source — e.g. a live JWKS refresher (ZT-2b) — so
// an IdP key rotation is picked up without a restart. The source's keyFor MUST NOT block on the network
// (the verify path is HTTP-free); a JWKSRefresher reads its background-refreshed snapshot. Returns the
// verifier for chaining.
func (v *OIDCVerifier) SetKeySource(keyFor func(kid string) (crypto.PublicKey, bool)) *OIDCVerifier {
	v.keyFor = keyFor
	return v
}

// WithClock overrides the clock (for tests). Returns the verifier for chaining.
func (v *OIDCVerifier) WithClock(now func() time.Time) *OIDCVerifier { v.now = now; return v }

// defaultLeeway is the clock-skew tolerance applied to exp/nbf when none is configured (R34-10).
const defaultLeeway = 60 * time.Second

// WithLeeway sets the allowed clock skew for exp/nbf checks (R34-10). A negative value is clamped to
// zero. Returns the verifier for chaining.
func (v *OIDCVerifier) WithLeeway(d time.Duration) *OIDCVerifier {
	if d < 0 {
		d = 0
	}
	v.leeway = d
	return v
}

// EnableDPoP turns on sender-constrained (DPoP) validation (R34-10): once on, a token that carries a
// `cnf.jkt` confirmation claim REQUIRES a matching DPoP proof (see VerifyWithProof), so a stolen
// bearer token cannot be replayed from a device that does not hold the bound key. capacity bounds the
// proof-replay cache. Returns the verifier for chaining.
func (v *OIDCVerifier) EnableDPoP(capacity int) *OIDCVerifier {
	if capacity <= 0 {
		capacity = 4096
	}
	v.dpopReplay = newSeenSet(capacity)
	return v
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"` // string OR []string per RFC 7519
	Exp int64           `json:"exp"`
	Nbf int64           `json:"nbf"`
	Cnf *struct {
		Jkt string `json:"jkt"` // RFC 9449 §6: base64url SHA-256 thumbprint of the bound key
	} `json:"cnf"`
	// The role claim is read dynamically (its name is configured), so claims are also
	// decoded into a generic map below.
}

// Verify validates a compact-serialized JWT and resolves it into an Identity (A.2b).
// EVERY check is fail-closed: a malformed token, an unknown key id, a bad signature, a
// wrong issuer/audience, an expired/not-yet-valid token, or a missing subject/role is an
// ERROR — never a partial or defaulted identity. The subject is pseudonymised one-way
// (D23) exactly as the client-cert producer does, so the raw `sub` never enters the
// pipeline; the role comes from the configured claim (an authorization class, carried in
// the clear like the cert's group).
func (v *OIDCVerifier) Verify(token string) (*Identity, error) {
	id, _, err := v.verify(token)
	return id, err
}

// verify is the shared core returning the resolved identity AND the decoded claims, so the
// sender-constrained path (VerifyWithProof) can read the `cnf` confirmation without re-parsing.
func (v *OIDCVerifier) verify(token string) (*Identity, jwtClaims, error) {
	h, claims, signing, sig, err := splitJWT(token)
	if err != nil {
		return nil, claims, err
	}

	key, ok := v.keyFor(h.Kid)
	if !ok {
		return nil, claims, fmt.Errorf("identity: OIDC token signed by unknown key id %q", h.Kid)
	}
	if err := verifySignature(h.Alg, key, signing, sig); err != nil {
		return nil, claims, err
	}

	if claims.Iss != v.issuer {
		return nil, claims, fmt.Errorf("identity: OIDC token issuer %q != expected %q", claims.Iss, v.issuer)
	}
	if !audienceContains(claims.Aud, v.audience) {
		return nil, claims, fmt.Errorf("identity: OIDC token audience does not include %q", v.audience)
	}
	now := v.now()
	leeway := v.leeway
	if leeway == 0 {
		leeway = defaultLeeway
	}
	// R34-10: apply the clock-skew leeway so sub-minute drift between the gateway and the IdP does
	// not spuriously reject a valid token (or reject one issued "just now" with nbf==iat).
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(leeway)) {
		return nil, claims, fmt.Errorf("identity: OIDC token is expired or has no expiry")
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-leeway)) {
		return nil, claims, fmt.Errorf("identity: OIDC token is not yet valid (nbf)")
	}
	if claims.Sub == "" {
		return nil, claims, fmt.Errorf("identity: OIDC token has no subject")
	}

	role, err := roleFromClaim(signing, v.roleClaim)
	if err != nil {
		return nil, claims, err
	}
	return &Identity{Subject: pseudonym(claims.Sub), Role: role}, claims, nil
}

// confirmationKey returns the token's DPoP-bound key thumbprint (cnf.jkt) and whether it is present.
func (c jwtClaims) confirmationKey() (string, bool) {
	if c.Cnf == nil || c.Cnf.Jkt == "" {
		return "", false
	}
	return c.Cnf.Jkt, true
}

// splitJWT parses the three-part compact serialization, returning the decoded header,
// the typed claims, the signing input ("header.payload"), and the raw signature bytes.
func splitJWT(token string) (jwtHeader, jwtClaims, []byte, []byte, error) {
	var h jwtHeader
	var c jwtClaims
	// A JWT is exactly header.payload.signature — no more, no fewer.
	var p1, p2, p3 string
	n := 0
	start := 0
	parts := [3]string{}
	for i := 0; i <= len(token); i++ {
		if i == len(token) || token[i] == '.' {
			if n >= 3 {
				return h, c, nil, nil, fmt.Errorf("identity: malformed JWT (too many segments)")
			}
			parts[n] = token[start:i]
			n++
			start = i + 1
		}
	}
	if n != 3 {
		return h, c, nil, nil, fmt.Errorf("identity: malformed JWT (want 3 segments, got %d)", n)
	}
	p1, p2, p3 = parts[0], parts[1], parts[2]

	hb, err := base64.RawURLEncoding.DecodeString(p1)
	if err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: JWT header not base64url: %w", err)
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: JWT header not JSON: %w", err)
	}
	cb, err := base64.RawURLEncoding.DecodeString(p2)
	if err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: JWT claims not base64url: %w", err)
	}
	if err := json.Unmarshal(cb, &c); err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: JWT claims not JSON: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(p3)
	if err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: JWT signature not base64url: %w", err)
	}
	return h, c, []byte(p1 + "." + p2), sig, nil
}

// verifySignature checks the token signature by algorithm. Only asymmetric algorithms
// are accepted — RS256 (the OIDC default) and EdDSA (consistent with the fleet's
// Ed25519 keys, D60). The `none` alg and symmetric HS* are REJECTED: `none` is the
// classic JWT bypass, and an HMAC verify against an RSA public key is the algorithm-
// confusion attack. The alg must match the configured key's type.
func verifySignature(alg string, key crypto.PublicKey, signing, sig []byte) error {
	switch alg {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("identity: token alg RS256 but key is not RSA")
		}
		sum := sha256.Sum256(signing)
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, sum[:], sig); err != nil {
			return fmt.Errorf("identity: OIDC token signature invalid (RS256)")
		}
		return nil
	case "EdDSA":
		edKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("identity: token alg EdDSA but key is not Ed25519")
		}
		if !ed25519.Verify(edKey, signing, sig) {
			return fmt.Errorf("identity: OIDC token signature invalid (EdDSA)")
		}
		return nil
	default:
		return fmt.Errorf("identity: unsupported or unsafe JWT alg %q (want RS256 or EdDSA)", alg)
	}
}

// audienceContains reports whether the token's `aud` (a string or an array of strings,
// per RFC 7519 §4.1.3) includes the expected audience.
func audienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return one == want
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// roleFromClaim reads the configured role claim from the payload. The claim may be a
// single string (a role) or an array of strings (groups) — the first non-empty value is
// the authorization group. A missing or empty role claim is an error: a token with no
// authorization class cannot be mapped to a policy role, and defaulting one would grant
// unearned access.
func roleFromClaim(signing []byte, claim string) (string, error) {
	// signing is "header.payload"; re-decode the payload generically for the dynamic claim.
	dot := -1
	for i := 0; i < len(signing); i++ {
		if signing[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return "", fmt.Errorf("identity: cannot read role claim (malformed signing input)")
	}
	cb, err := base64.RawURLEncoding.DecodeString(string(signing[dot+1:]))
	if err != nil {
		return "", fmt.Errorf("identity: cannot decode claims for role: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(cb, &m); err != nil {
		return "", fmt.Errorf("identity: cannot parse claims for role: %w", err)
	}
	raw, ok := m[claim]
	if !ok {
		return "", fmt.Errorf("identity: OIDC token missing role claim %q", claim)
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return one, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, g := range many {
			if g != "" {
				return g, nil
			}
		}
	}
	return "", fmt.Errorf("identity: OIDC token role claim %q is empty", claim)
}

// LoadOIDCKeys loads a directory of PEM public keys into a kid→key map for the OIDC verifier (ZT-2).
// Each file "<kid>.pem" is a PKIX public key (RSA or Ed25519); the filename (minus .pem) is the kid
// a JWT header must reference. This is the static-key wiring; LIVE JWKS discovery (fetching + caching
// the issuer's rotating keys) is a conscious follow-up — the gateway is a chokepoint, so an outbound
// JWKS fetch there wants its own timeout/failure posture, not a silent dependency.
func LoadOIDCKeys(dir string) (map[string]crypto.PublicKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".pem") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("identity: %s is not PEM", name)
		}
		pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identity: %s: %w", name, err)
		}
		keys[strings.TrimSuffix(name, ".pem")] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("identity: no .pem keys in %s", dir)
	}
	return keys, nil
}
