package identity

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwk is one key of a JWKS document (the subset the two supported algorithms use).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	N   string `json:"n"` // RSA modulus (base64url)
	E   string `json:"e"` // RSA exponent (base64url)
	X   string `json:"x"` // OKP/Ed25519 public key (base64url)
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

const defaultJWKSMinGap = 30 * time.Second

// JWKSRefresher keeps a background-refreshed kid→key snapshot from a JWKS endpoint (ZT-2b/ADR-7), so an
// identity-provider key rotation is picked up without a restart. Three properties are load-bearing:
// it SERVES STALE on a fetch failure (auth availability is decoupled from the IdP), it RATE-LIMITS a
// refresh triggered by an unknown key id (an unknown-kid flood cannot hammer the IdP), and it NEVER
// fetches on the request path (KeyFor only reads the snapshot; all HTTP is in Start's goroutine).
type JWKSRefresher struct {
	url      string
	client   *http.Client
	interval time.Duration
	minGap   time.Duration
	now      func() time.Time

	mu       sync.RWMutex
	snapshot map[string]crypto.PublicKey

	rateMu      sync.Mutex
	lastRefresh time.Time
	trigger     chan struct{}
}

// NewJWKSRefresher builds a refresher over a JWKS URL, refreshing on the given interval.
func NewJWKSRefresher(url string, interval time.Duration) *JWKSRefresher {
	return &JWKSRefresher{
		url:      url,
		client:   &http.Client{Timeout: 5 * time.Second},
		interval: interval,
		minGap:   defaultJWKSMinGap,
		now:      time.Now,
		snapshot: map[string]crypto.PublicKey{},
		trigger:  make(chan struct{}, 1),
	}
}

// WithMinGap sets the minimum interval between kid-miss-triggered refreshes (the rate limit).
// Returns the refresher for chaining.
func (r *JWKSRefresher) WithMinGap(d time.Duration) *JWKSRefresher { r.minGap = d; return r }

// KeyFor resolves a key id against the current snapshot. On a MISS it signals a background refresh
// (non-blocking) and returns not-found — it NEVER performs a network fetch, so the token-verification
// path stays HTTP-free. Wire it into an OIDCVerifier via SetKeySource.
func (r *JWKSRefresher) KeyFor(kid string) (crypto.PublicKey, bool) {
	r.mu.RLock()
	k, ok := r.snapshot[kid]
	r.mu.RUnlock()
	if !ok {
		select {
		case r.trigger <- struct{}{}: // signal a refresh; a rotation likely added this kid
		default: // one is already pending — coalesce
		}
	}
	return k, ok
}

// Start runs the refresh loop until ctx is done: an immediate refresh, then on the interval ticker and
// on a kid-miss trigger — a trigger-driven refresh is SKIPPED if within minGap of the last successful
// refresh (the rate limit).
func (r *JWKSRefresher) Start(ctx context.Context) {
	_ = r.doRefresh(ctx) // prime the snapshot; an error leaves it empty (serve-stale from nothing yet)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.doRefresh(ctx)
		case <-r.trigger:
			r.rateMu.Lock()
			gapOK := r.now().Sub(r.lastRefresh) >= r.minGap
			r.rateMu.Unlock()
			if gapOK {
				_ = r.doRefresh(ctx)
			}
		}
	}
}

// doRefresh fetches + parses the JWKS and atomically swaps the snapshot. On ANY error it returns the
// error and LEAVES the previous snapshot in place (serve-stale). lastRefresh is stamped only on a
// SUCCESS, so a failed fetch does not consume the rate-limit window.
func (r *JWKSRefresher) doRefresh(ctx context.Context) error {
	keys, err := r.fetch(ctx)
	if err != nil {
		return err // keep the last-good snapshot
	}
	r.mu.Lock()
	r.snapshot = keys
	r.mu.Unlock()
	r.rateMu.Lock()
	r.lastRefresh = r.now()
	r.rateMu.Unlock()
	return nil
}

func (r *JWKSRefresher) fetch(ctx context.Context) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity: JWKS fetch %s: status %d", r.url, resp.StatusCode)
	}
	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("identity: JWKS decode: %w", err)
	}
	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kid == "" {
			continue
		}
		if pk, ok := parseJWK(k); ok {
			out[k.Kid] = pk
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("identity: JWKS %s yielded no usable keys", r.url)
	}
	return out, nil
}

// parseJWK converts a JWK into a crypto.PublicKey for the two algorithms the verifier accepts — RSA
// and Ed25519. Any other key type (or a malformed one) is skipped, never trusted.
func parseJWK(k jwk) (crypto.PublicKey, bool) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil || len(nb) == 0 {
			return nil, false
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(eb) == 0 {
			return nil, false
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		if e == 0 {
			return nil, false
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, true
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, false
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(xb) != ed25519.PublicKeySize {
			return nil, false
		}
		return ed25519.PublicKey(xb), true
	}
	return nil, false
}
