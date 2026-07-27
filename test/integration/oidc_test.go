//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SSO IDENTITY ON THE ACCESS PROXY (ZT-2), against the running binary (D316).
//
// Eleven declared settings — issuer, audience, role claim, key directory, JWKS URL and interval, leeway,
// DPoP and its cache — and NOT ONE was exercised by this suite. The verifier's own package tests are
// thorough about the cryptography; what none of them can show is whether `main()` reaches the verifier,
// whether a rejected token actually stops a request, or whether the role a token carries reaches the
// policy that is supposed to act on it.
//
// That gap matters more here than in most places, because ZT-2 is the layer that answers WHO. The mTLS
// certificate says which DEVICE; the token says which PERSON. A gateway that verified device identity
// perfectly and quietly ignored the token would admit anyone holding a laptop.
//
// THE ASSERTIONS ARE ON ACCESS DECISIONS AND ON THE ORIGIN, never on a startup line. A 403 to the client
// proves the gateway answered; only an untouched origin proves the request did not arrive.

// signJWT mints an EdDSA (Ed25519) token. Everything is real: a real key, a real signature, a real
// verification by the running gateway.
//
// EdDSA RATHER THAN ES256, and the first version got this wrong in a way worth recording. The verifier
// accepts RS256 and EdDSA ONLY — it refuses ES256 by design, as part of refusing "unsupported or unsafe"
// algorithms rather than verifying whatever a token asks for. Signing with ES256 meant EVERY token in
// this file was rejected, and because the negative cases all assert "not 200", THEY ALL PASSED. Only the
// positive case failed. That is the vacuous-negative trap in its purest form: seven tests green, one red,
// and the seven were proving nothing at all.
func signJWT(t *testing.T, key ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid}) + "." + enc(claims)
	return signing + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signing)))
}

// writeOIDCKey writes the verifier's key directory: <kid>.pem, PKIX public key.
func writeOIDCKey(t *testing.T, dir, kid string, key ed25519.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, kid+".pem"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
}

func newSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// ssoOnlyPolicy authorises on the ROLE THE TOKEN CARRIES, so a decision changes only if the token was
// verified and its claim reached the policy input. A policy keyed on the certificate instead would pass
// whether or not the token was read at all.
const ssoOnlyPolicy = `package openshield
import rego.v1
authorized if { input.context.role == "finance" }
decision := {"action":"ALLOW","reason":"sso role","confidence":0.9} if { authorized }
decision := {"action":"BLOCK","reason":"role not authorized","confidence":0.9} if { not authorized }`

type ssoStack struct {
	addr   string
	origin *upstream
	pki    *pki
	keyDir string
	issuer string
	// startFn is deferred so a test can write the signing key BEFORE the gateway boots. A
	// misconfigured OIDC block aborts startup — correct for a zero-trust gate, and it means the key
	// has to be on disk first.
	startFn func() *Process
}

func startSSOGateway(t *testing.T, extra ...string) *ssoStack {
	t.Helper()
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	origin := startUpstream(t)
	work := t.TempDir()

	policyPath := filepath.Join(work, "sso.rego")
	if err := os.WriteFile(policyPath, []byte(ssoOnlyPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	m := p.serverMaterial(t)
	addr := "127.0.0.1:" + freePort(t)
	keyDir := filepath.Join(work, "oidc-keys")
	const issuer = "https://idp.integration.test"

	env := append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_ACCESS_MODE=1",
		"OPENSHIELD_ACCESS_LISTEN=" + addr,
		"OPENSHIELD_ACCESS_CLIENT_CA=" + p.caPEM,
		"OPENSHIELD_ACCESS_SERVER_CERT=" + m.Cert,
		"OPENSHIELD_ACCESS_SERVER_KEY=" + m.Key,
		"OPENSHIELD_ACCESS_POLICY=" + policyPath,
		"OPENSHIELD_ACCESS_CATALOG=payroll=http://" + origin.addr,
		"OPENSHIELD_OIDC_ISSUER=" + issuer,
		"OPENSHIELD_OIDC_AUDIENCE=openshield",
		"OPENSHIELD_OIDC_ROLE_CLAIM=groups",
		"OPENSHIELD_OIDC_KEYS_DIR=" + keyDir,
		"OPENSHIELD_OIDC_LEEWAY=5s",
	}, extra...)

	s := &ssoStack{addr: addr, origin: origin, pki: p, keyDir: keyDir, issuer: issuer}
	s.startFn = func() *Process {
		gw := Start(t, "openshield-gateway", env)
		gw.WaitForOutput("OIDC SSO identity enabled", 90*time.Second)
		waitTCP(t, addr, 60*time.Second)
		return gw
	}
	return s
}

func (s *ssoStack) client(t *testing.T, token string) *http.Client {
	t.Helper()
	cert := s.pki.leafCert(t, "client", "sso-device", "--group", "devices")
	caPEM, err := os.ReadFile(s.pki.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the CA certificate did not parse")
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &bearerTransport{token: token, rt: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert}, RootCAs: pool,
				ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
			},
			// The catalog resolves by HOST, so the request names the service and the dial goes to the
			// proxy — the same shape a client behind DNS would have.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, s.addr)
			},
		}},
	}
}

// TestAValidSSOTokenAuthorizesAndAnInvalidOneDoesNot is the pair that makes either half mean something.
func TestAValidSSOTokenAuthorizesAndAnInvalidOneDoesNot(t *testing.T) {
	s := startSSOGateway(t)
	good := newSigningKey(t)
	writeOIDCKey(t, s.keyDir, "k1", good)
	s.startFn()

	now := time.Now()
	claims := func(groups any) map[string]any {
		return map[string]any{
			"iss": s.issuer, "aud": "openshield", "sub": "person-1",
			"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
			"groups": groups,
		}
	}

	// 1. A token signed by the ENROLLED key, carrying the authorised role.
	resp := get(t, s.client(t, signJWT(t, good, "k1", claims("finance"))), "https://payroll/report")
	if resp != http.StatusOK {
		t.Fatalf("a valid SSO token with the authorised role got %d, want 200 — the token's claim is what "+
			"the policy authorises on, so this failing means the token never reached the policy", resp)
	}
	before := s.origin.hits.Load()
	if before == 0 {
		t.Fatal("the proxy returned 200 and the origin was never reached")
	}

	// 2. THE SAME KEY, THE WRONG ROLE. The token verifies; authorization still refuses. Without this a
	// gateway that admitted every VERIFIED token would pass, which is a real and common bug: verification
	// and authorization are different questions.
	if code := get(t, s.client(t, signJWT(t, good, "k1", claims("interns"))), "https://payroll/report"); code == http.StatusOK {
		t.Error("a verified token with an UNAUTHORISED role was admitted — verifying who someone is, is " +
			"not deciding what they may reach")
	}

	// 3. A TOKEN SIGNED BY A KEY THE GATEWAY DOES NOT HOLD, with the authorised role and the right kid.
	// This is the forgery case, and the only one that distinguishes a real signature check from a parser
	// that reads claims and believes them.
	forged := newSigningKey(t)
	if code := get(t, s.client(t, signJWT(t, forged, "k1", claims("finance"))), "https://payroll/report"); code == http.StatusOK {
		t.Error("a token signed by an UNKNOWN key was accepted. Every claim in a JWT is attacker-chosen " +
			"until the signature is checked, so this would mean anyone can mint themselves any role")
	}
	if after := s.origin.hits.Load(); after != before {
		t.Errorf("the origin received %d more request(s) from refused tokens", after-before)
	}
}

// TestAnExpiredTokenIsRefusedBeyondTheLeeway.
//
// Expiry is what makes a token a session rather than a credential. The leeway exists because clocks
// disagree, and this checks it is a LEEWAY and not an amnesty: a token expired well past it must fail.
func TestAnExpiredTokenIsRefusedBeyondTheLeeway(t *testing.T) {
	s := startSSOGateway(t)
	key := newSigningKey(t)
	writeOIDCKey(t, s.keyDir, "k1", key)
	s.startFn()

	now := time.Now()
	expired := signJWT(t, key, "k1", map[string]any{
		"iss": s.issuer, "aud": "openshield", "sub": "person-1",
		"iat":    now.Add(-2 * time.Hour).Unix(),
		"exp":    now.Add(-time.Hour).Unix(), // an hour past, against a 5s leeway
		"groups": "finance",
	})
	if code := get(t, s.client(t, expired), "https://payroll/report"); code == http.StatusOK {
		t.Error("an EXPIRED token was accepted. Expiry is what makes a token a session rather than a " +
			"permanent credential; a stolen token would then be usable forever")
	}
}

// TestATokenForAnotherAudienceIsRefused.
//
// The `aud` claim is what stops a token minted for a DIFFERENT service being replayed at this one. An IdP
// commonly issues tokens for many audiences from one key, so a verifier that checks the signature and not
// the audience accepts every one of them — and the signature will be perfectly valid.
func TestATokenForAnotherAudienceIsRefused(t *testing.T) {
	s := startSSOGateway(t)
	key := newSigningKey(t)
	writeOIDCKey(t, s.keyDir, "k1", key)
	s.startFn()

	now := time.Now()
	other := signJWT(t, key, "k1", map[string]any{
		"iss": s.issuer, "aud": "some-other-service", "sub": "person-1",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
		"groups": "finance",
	})
	if code := get(t, s.client(t, other), "https://payroll/report"); code == http.StatusOK {
		t.Error("a token minted for ANOTHER AUDIENCE was accepted here. One IdP key signs tokens for many " +
			"services, so without the audience check a token issued for any of them opens this one")
	}
}

// TestATokenFromAnotherIssuerIsRefused. The issuer is the trust anchor's name; accepting any issuer means
// a token from an IdP this deployment has never heard of is as good as one from its own.
func TestATokenFromAnotherIssuerIsRefused(t *testing.T) {
	s := startSSOGateway(t)
	key := newSigningKey(t)
	writeOIDCKey(t, s.keyDir, "k1", key)
	s.startFn()

	now := time.Now()
	foreign := signJWT(t, key, "k1", map[string]any{
		"iss": "https://attacker.example", "aud": "openshield", "sub": "person-1",
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
		"groups": "finance",
	})
	if code := get(t, s.client(t, foreign), "https://payroll/report"); code == http.StatusOK {
		t.Error("a token from an UNKNOWN ISSUER was accepted")
	}
}

// TestNoTokenIsRefusedWhenSSOIsRequired: the device certificate alone must not be enough once the
// deployment has said identity comes from a token. mTLS says which LAPTOP; it does not say which PERSON.
func TestNoTokenIsRefusedWhenSSOIsRequired(t *testing.T) {
	s := startSSOGateway(t)
	key := newSigningKey(t)
	writeOIDCKey(t, s.keyDir, "k1", key)
	s.startFn()

	if code := get(t, s.client(t, ""), "https://payroll/report"); code == http.StatusOK {
		t.Error("a request with a valid device certificate and NO TOKEN was admitted. The certificate " +
			"identifies the machine; anyone holding that machine would then reach the service")
	}
}

// TestAMisconfiguredOIDCBlockAbortsStartup.
//
// A zero-trust gate that comes up with a broken identity source is worse than one that does not come up:
// the first admits requests it cannot attribute, and looks healthy doing it.
func TestAMisconfiguredOIDCBlockAbortsStartup(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	work := t.TempDir()
	policyPath := filepath.Join(work, "sso.rego")
	if err := os.WriteFile(policyPath, []byte(ssoOnlyPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	m := p.serverMaterial(t)

	out, err := runCapture(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_ACCESS_MODE=1",
		"OPENSHIELD_ACCESS_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_ACCESS_CLIENT_CA=" + p.caPEM,
		"OPENSHIELD_ACCESS_SERVER_CERT=" + m.Cert,
		"OPENSHIELD_ACCESS_SERVER_KEY=" + m.Key,
		"OPENSHIELD_ACCESS_POLICY=" + policyPath,
		"OPENSHIELD_ACCESS_CATALOG=payroll=http://127.0.0.1:1",
		"OPENSHIELD_OIDC_ISSUER=https://idp.integration.test",
		// A key directory that does not exist.
		"OPENSHIELD_OIDC_KEYS_DIR=" + filepath.Join(work, "no-such-dir"),
	})
	if err == nil {
		t.Fatalf("the gateway STARTED with an unreadable OIDC key directory:\n%s", out)
	}
	if !contains(out, "OIDC") {
		t.Errorf("the refusal does not name OIDC, so an operator cannot tell what is misconfigured:\n%s", out)
	}
}

// TestAPlaintextJWKSURLIsRefused is R34-3: the key source decides who may mint an identity.
//
// Fetching signing keys over plain HTTP means anyone on the path can substitute their own and issue
// themselves any role — the gateway would then verify forged tokens perfectly. A ZT gate must not boot on
// a key source it cannot authenticate.
func TestAPlaintextJWKSURLIsRefused(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	p := newPKI(t)
	work := t.TempDir()
	policyPath := filepath.Join(work, "sso.rego")
	if err := os.WriteFile(policyPath, []byte(ssoOnlyPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	m := p.serverMaterial(t)

	out, err := runCapture(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_ACCESS_MODE=1",
		"OPENSHIELD_ACCESS_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_ACCESS_CLIENT_CA=" + p.caPEM,
		"OPENSHIELD_ACCESS_SERVER_CERT=" + m.Cert,
		"OPENSHIELD_ACCESS_SERVER_KEY=" + m.Key,
		"OPENSHIELD_ACCESS_POLICY=" + policyPath,
		"OPENSHIELD_ACCESS_CATALOG=payroll=http://127.0.0.1:1",
		"OPENSHIELD_OIDC_ISSUER=https://idp.integration.test",
		"OPENSHIELD_OIDC_JWKS_URL=http://idp.integration.test/jwks",
	})
	if err == nil {
		t.Fatalf("the gateway started with a PLAINTEXT JWKS URL:\n%s", out)
	}
}

// bearerTransport attaches the token, or nothing when it is empty.
type bearerTransport struct {
	token string
	rt    http.RoundTripper
}

func (b *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.rt.RoundTrip(r)
}

func get(t *testing.T, c *http.Client, url string) int {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}
