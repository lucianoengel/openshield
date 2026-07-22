package identity

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// dpopProofWindow bounds how far a DPoP proof's `iat` may be from now (RFC 9449 §4.3): a proof is a
// per-request, short-lived artifact, so a wide window would let a captured proof be replayed against a
// different backend before its jti is seen there. Symmetric to absorb clock skew both ways.
const dpopProofWindow = 2 * time.Minute

// seenSet is a bounded, FIFO-evicting set of recently-seen ids — a DPoP proof jti cache (R34-10). The
// same shape as the control plane's notify dedupe: the id ages out and the size cap bounds memory.
type seenSet struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
	cap   int
}

func newSeenSet(capacity int) *seenSet {
	return &seenSet{seen: make(map[string]struct{}, capacity), cap: capacity}
}

// markNew records id and reports true if it was NOT already present (a genuinely new proof); false
// means this jti was already used — a replay to reject.
func (s *seenSet) markNew(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[id]; ok {
		return false
	}
	s.seen[id] = struct{}{}
	s.order = append(s.order, id)
	if len(s.order) > s.cap {
		evict := s.order[0]
		s.order = s.order[1:]
		delete(s.seen, evict)
	}
	return true
}

// dpopHeader is the DPoP proof's JOSE header: it carries the PUBLIC key (as a JWK) whose private half
// signed the proof. The thumbprint of this key must equal the access token's cnf.jkt.
type dpopHeader struct {
	Typ string          `json:"typ"`
	Alg string          `json:"alg"`
	Jwk json.RawMessage `json:"jwk"`
}

// dpopClaims are the proof's payload: the HTTP method + URI it is bound to, its freshness, and its
// unique id (RFC 9449 §4.2).
type dpopClaims struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

// VerifyWithProof validates a bearer token AND, when the token is sender-constrained (carries a
// `cnf.jkt`), the accompanying DPoP proof binds the request to the confirmed key (R34-10). method and
// requestURI are the HTTP method and the URI the proof must be bound to (htm/htu). A token WITHOUT a
// cnf.jkt verifies exactly as Verify (a non-DPoP deployment is unaffected); a token WITH a cnf.jkt but
// no/invalid proof is REJECTED — that is the whole point, a stolen bearer token is useless without the
// bound key. When DPoP is not enabled on the verifier, cnf is ignored (Verify semantics).
func (v *OIDCVerifier) VerifyWithProof(token, dpopProof, method, requestURI string) (*Identity, error) {
	id, claims, err := v.verify(token)
	if err != nil {
		return nil, err
	}
	jkt, bound := claims.confirmationKey()
	if v.dpopReplay == nil || !bound {
		// Sender-constraining off, or the token is not bound — plain bearer semantics.
		return id, nil
	}
	if dpopProof == "" {
		return nil, fmt.Errorf("identity: token is sender-constrained (cnf.jkt) but no DPoP proof was presented")
	}
	if err := v.validateDPoP(dpopProof, jkt, method, requestURI); err != nil {
		return nil, err
	}
	return id, nil
}

// validateDPoP checks a DPoP proof against the token's confirmed key thumbprint and the request.
func (v *OIDCVerifier) validateDPoP(proof, wantJkt, method, requestURI string) error {
	h, c, signing, sig, err := splitDPoP(proof)
	if err != nil {
		return err
	}
	if h.Typ != "dpop+jwt" {
		return fmt.Errorf("identity: DPoP proof has wrong typ %q", h.Typ)
	}
	pub, thumb, err := parseDPoPJWK(h.Jwk)
	if err != nil {
		return err
	}
	// The proof's embedded key MUST be the one the token was bound to — else a fresh, correctly-formed
	// proof under an ATTACKER's key would pass. Constant-time-ish string compare of base64url thumbs.
	if thumb != wantJkt {
		return fmt.Errorf("identity: DPoP proof key does not match the token's bound key (cnf.jkt)")
	}
	if err := verifySignature(h.Alg, pub, signing, sig); err != nil {
		return fmt.Errorf("identity: DPoP proof signature invalid: %w", err)
	}
	if c.Htm != method {
		return fmt.Errorf("identity: DPoP proof method %q != request method %q", c.Htm, method)
	}
	if c.Htu != requestURI {
		return fmt.Errorf("identity: DPoP proof URI %q != request URI %q", c.Htu, requestURI)
	}
	now := v.now()
	if c.Iat == 0 || now.Sub(time.Unix(c.Iat, 0)) > dpopProofWindow || time.Unix(c.Iat, 0).Sub(now) > dpopProofWindow {
		return fmt.Errorf("identity: DPoP proof iat is missing or outside the freshness window")
	}
	if c.Jti == "" {
		return fmt.Errorf("identity: DPoP proof has no jti")
	}
	// Single-use: a proof jti may be presented once. This is what actually blocks replay — even a
	// captured, still-fresh proof for the right key + request cannot be reused.
	if !v.dpopReplay.markNew(c.Jti) {
		return fmt.Errorf("identity: DPoP proof jti replayed")
	}
	return nil
}

// splitDPoP parses a compact DPoP proof JWT into its header, claims, signing input, and signature.
func splitDPoP(proof string) (dpopHeader, dpopClaims, []byte, []byte, error) {
	var h dpopHeader
	var c dpopClaims
	parts := splitCompact(proof)
	if parts == nil {
		return h, c, nil, nil, fmt.Errorf("identity: DPoP proof is not a compact JWT (want 3 segments)")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: DPoP header base64: %w", err)
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: DPoP header json: %w", err)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: DPoP claims base64: %w", err)
	}
	if err := json.Unmarshal(cb, &c); err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: DPoP claims json: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return h, c, nil, nil, fmt.Errorf("identity: DPoP signature base64: %w", err)
	}
	signing := []byte(parts[0] + "." + parts[1])
	return h, c, signing, sig, nil
}

// parseDPoPJWK decodes the proof's embedded JWK into a crypto.PublicKey (reusing the verifier's
// key parsing) and computes its RFC 7638 thumbprint (base64url SHA-256 of the canonical JSON with
// lexically-ordered required members and no whitespace).
func parseDPoPJWK(raw json.RawMessage) (crypto.PublicKey, string, error) {
	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", fmt.Errorf("identity: DPoP jwk json: %w", err)
	}
	pub, ok := parseJWK(k)
	if !ok {
		return nil, "", fmt.Errorf("identity: DPoP jwk is not a usable RSA/Ed25519 key")
	}
	var canon string
	switch k.Kty {
	case "RSA":
		canon = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N) // RFC 7638 §3.2
	case "OKP":
		canon = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, k.Crv, k.X) // RFC 8037 §2
	default:
		return nil, "", fmt.Errorf("identity: DPoP jwk kty %q unsupported", k.Kty)
	}
	return pub, thumbprint(canon), nil
}

func thumbprint(canonicalJSON string) string {
	sum := sha256.Sum256([]byte(canonicalJSON))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// splitCompact splits a compact JWS "a.b.c" into exactly three non-empty-delimited segments, or nil if
// it does not have exactly three segments.
func splitCompact(s string) []string {
	parts := [3]string{}
	n := 0
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if n >= 3 {
				return nil
			}
			parts[n] = s[start:i]
			n++
			start = i + 1
		}
	}
	if n != 3 {
		return nil
	}
	return parts[:]
}
