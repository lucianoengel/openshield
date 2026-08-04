package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CONSOLE-1: THE MACHINE PRINCIPAL HAD A NAMESPACE AND NO CREDENTIAL.
//
// `svc:<name>` parses, can be granted a tier, and is refused four-eyes (D469) — but nothing could ever
// PRESENT one. `authenticateOperator` mints `cert:` from a verified certificate and `oidc:` from a
// verified token, and there was no third path, so every `svc:` row in `operator_roles` authorized a
// caller that could not exist.
//
// That is not a harmless gap. It is exactly the pressure that puts an automation on a HUMAN's
// credential: the integration needs to call the operator API, the only credentials that work are a
// person's certificate and a person's SSO token, so somebody issues one "for the runner". Every control
// that reasons about "a different person" then reasons about a shared secret — and two-person approval
// is the specific casualty, because a service account holding a human's second credential is precisely
// the second string the account comparison exists to collapse.
//
// # WHY A CONTROL-PLANE-ISSUED TOKEN AND NOT A CERTIFICATE
//
// A machine credential needs a lifecycle: issue, expire, rotate, revoke. A certificate gets that from a
// CA, and reaching a CA is an operational dependency the automation's owner may not have — which is
// how "just use mine" wins again. The control plane already owns the authorization table, so it can own
// the credential and make expiry non-optional.
//
// # EXPIRY IS MANDATORY, WITH A CEILING
//
// There is no "never expires" and no default. A non-expiring automation credential is the one nobody
// rotates: it outlives the integration, the project and the person who issued it, and it is still valid.
// `MaxMachineCredentialTTL` caps it, so the worst case an operator can create is bounded even when they
// are trying to avoid the renewal.
//
// # WHAT IS STORED
//
// The SHA-256 of the secret, never the secret. Issuance is the only time the plaintext exists, and it is
// printed once. A leaked database therefore yields no working credential — the same reason the enrolment
// tokens (D44) are stored hashed.
//
// A machine token is a bearer secret held by a machine, so DPoP does not apply to it: there is no
// browser, no redirect, and no user agent to bind a proof to. Its defence is a short, mandatory life and
// one-command revocation.

// MachineTokenPrefix marks a credential as this system's machine token.
//
// PRESENT SO AUTHENTICATION NEVER GUESSES. The operator surface already accepts OIDC bearer tokens on
// the same header, and a machine token handed to the OIDC verifier would fail there with a message about
// the identity provider — sending whoever debugs it to the wrong system entirely. The prefix decides
// which verifier sees it, before either one runs.
//
// It also makes the secret recognisable in a log or a repository, which is what lets scanning find one
// that leaked.
const MachineTokenPrefix = "osm_"

// MaxMachineCredentialTTL is the longest life a machine credential may be issued for.
//
// 90 days. Long enough that renewal is a quarterly chore rather than a weekly interruption — the
// threshold above which people automate around the control instead of with it — and short enough that a
// credential forgotten in a CI variable stops working while the project that used it still exists.
const MaxMachineCredentialTTL = 90 * 24 * time.Hour

var (
	// ErrMachineCredentialExpiry is returned when the requested life is absent, zero, negative, or beyond
	// the ceiling.
	ErrMachineCredentialExpiry = errors.New("controlplane: a machine credential must expire, within the maximum")
	// ErrNoMachineCredential is returned when a named credential does not exist.
	ErrNoMachineCredential = errors.New("controlplane: no such machine credential")
)

// MachineCredential is one issued machine credential, without its secret.
type MachineCredential struct {
	Principal string
	IssuedAt  time.Time
	ExpiresAt time.Time
	IssuedBy  string
	Revoked   bool
	// LastUsedAt is zero until the credential authenticates something. An automation credential that has
	// never been used is either not deployed yet or not needed, and both are worth seeing in a review.
	LastUsedAt time.Time
	// Rotations counts how many times the secret was replaced, so a review can tell a credential that is
	// maintained from one that was issued once and forgotten.
	Rotations int
}

// Expired reports whether this credential is past its life, at t.
func (m MachineCredential) Expired(t time.Time) bool { return !t.Before(m.ExpiresAt) }

// IssueMachineCredential mints a credential for `svc:<name>` and returns the plaintext token ONCE.
//
// It grants NOTHING. The principal still needs a row in `operator_roles`, exactly like a human, which
// keeps one answer to "what may this caller do" rather than two. Issuing a credential that also granted
// a tier would make the issuing command the place authorization is decided, and it is not.
func (s *Server) IssueMachineCredential(ctx context.Context, name string, ttl time.Duration, by string) (string, error) {
	p, err := servicePrincipal(name)
	if err != nil {
		return "", err
	}
	if err := checkMachineTTL(ttl); err != nil {
		return "", err
	}
	secret, hash, err := newMachineSecret()
	if err != nil {
		return "", err
	}
	// ON CONFLICT UPDATE rather than an error, because re-issuing to a name that already exists is the
	// ordinary recovery from a lost secret and refusing it would push an operator toward a second name
	// for the same automation — two credentials where they wanted one.
	_, err = s.pool.Exec(ctx,
		`INSERT INTO machine_credentials (principal, secret_sha256, issued_at, expires_at, issued_by, revoked)
		 VALUES ($1,$2,now(),$3,$4,false)
		 ON CONFLICT (principal) DO UPDATE SET secret_sha256 = EXCLUDED.secret_sha256,
		     issued_at = now(), expires_at = EXCLUDED.expires_at, issued_by = EXCLUDED.issued_by,
		     revoked = false, rotations = machine_credentials.rotations + 1`,
		p.String(), hash, time.Now().Add(ttl).UTC(), by)
	if err != nil {
		return "", err
	}
	return secret, nil
}

// RotateMachineCredential replaces the secret, keeping the principal and its grants.
//
// THE OLD SECRET STOPS WORKING IMMEDIATELY. There is no overlap window, and that is a decision rather
// than an omission: an overlap means two live secrets for one identity, and the whole point of rotation
// is that the previous one is gone. The cost is that the automation must be updated in the same change,
// which is the same cost as any other secret rotation and is visible rather than silent.
func (s *Server) RotateMachineCredential(ctx context.Context, name string, ttl time.Duration, by string) (string, error) {
	p, err := servicePrincipal(name)
	if err != nil {
		return "", err
	}
	if err := checkMachineTTL(ttl); err != nil {
		return "", err
	}
	secret, hash, err := newMachineSecret()
	if err != nil {
		return "", err
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE machine_credentials SET secret_sha256 = $2, issued_at = now(), expires_at = $3,
		     issued_by = $4, revoked = false, rotations = rotations + 1
		   WHERE principal = $1`, p.String(), hash, time.Now().Add(ttl).UTC(), by)
	if err != nil {
		return "", err
	}
	// ROTATION DOES NOT CREATE. Rotating a name that does not exist would issue a credential for whatever
	// the operator typed — including a typo — and report success.
	if tag.RowsAffected() == 0 {
		return "", fmt.Errorf("%w: %s", ErrNoMachineCredential, p.String())
	}
	return secret, nil
}

// RevokeMachineCredential stops a machine credential authenticating, immediately.
//
// A ROW, NOT A DELETE, for the reason RevokeOperator gives: a deleted row leaves nothing that records
// the credential ever existed, and an access review needs to see a revocation rather than infer it from
// an absence. It is also idempotent — revoking twice is not an error, because the second caller wanted
// the same end state.
func (s *Server) RevokeMachineCredential(ctx context.Context, name, by string) error {
	p, err := servicePrincipal(name)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE machine_credentials SET revoked = true, issued_by = $2 WHERE principal = $1`,
		p.String(), by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrNoMachineCredential, p.String())
	}
	return nil
}

// ListMachineCredentials returns every machine credential, revoked and expired ones included — both are
// facts a review needs to see.
func (s *Server) ListMachineCredentials(ctx context.Context) ([]MachineCredential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT principal, issued_at, expires_at, issued_by, revoked,
		        coalesce(last_used_at, 'epoch'::timestamptz), rotations
		   FROM machine_credentials ORDER BY principal`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MachineCredential
	for rows.Next() {
		var m MachineCredential
		if err := rows.Scan(&m.Principal, &m.IssuedAt, &m.ExpiresAt, &m.IssuedBy, &m.Revoked,
			&m.LastUsedAt, &m.Rotations); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// authenticateMachine resolves a machine token to its principal, or reports that it is not one.
//
// FAIL-CLOSED AT EVERY STEP, and the ordering matters: a token that is malformed, unknown, revoked or
// expired all produce the same answer — no principal — because distinguishing them for the caller would
// let an attacker enumerate which service names exist.
func (s *Server) authenticateMachine(ctx context.Context, token string) (operatorPrincipal, bool) {
	if !strings.HasPrefix(token, MachineTokenPrefix) {
		return operatorPrincipal{}, false
	}
	s.mu.Lock()
	pool := s.pool
	s.mu.Unlock()
	if pool == nil {
		return operatorPrincipal{}, false
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	var principal, stored string
	var expires time.Time
	var revoked bool
	err := pool.QueryRow(ctx,
		`SELECT principal, secret_sha256, expires_at, revoked FROM machine_credentials
		  WHERE secret_sha256 = $1`, hash).Scan(&principal, &stored, &expires, &revoked)
	if err != nil {
		// NO ROW AND A DATABASE ERROR REFUSE ALIKE. They are different facts — "this secret is not ours"
		// versus "we cannot tell" — and authentication has one safe answer to both. Written as a single
		// branch with this note rather than two identical ones, so that nobody later reads the second as
		// an unfinished thought and "improves" the unknown case into a fallback. Authorization is the one
		// place this project never fails open (see resolveOperatorRole).
		return operatorPrincipal{}, false
	}
	// The index lookup already matched, so this comparison is belt-and-braces against a future change
	// that widens the query. Constant-time regardless: a secret comparison that short-circuits is a
	// secret comparison somebody can time.
	if subtle.ConstantTimeCompare([]byte(stored), []byte(hash)) != 1 {
		return operatorPrincipal{}, false
	}
	if revoked {
		return operatorPrincipal{}, false
	}
	// EXPIRY IS CHECKED HERE, not only at issue. A credential whose life has run out must stop working
	// without anyone running a cleanup job — an expiry enforced by a sweeper is an expiry that does not
	// hold while the sweeper is down.
	now := time.Now()
	if !now.Before(expires) {
		return operatorPrincipal{}, false
	}
	p, err := parsePrincipal(principal)
	if err != nil || !p.isMachine() {
		// A stored principal that is not a machine means the row was written by something other than this
		// file. It authenticates nothing rather than being trusted on the strength of being in the table.
		return operatorPrincipal{}, false
	}
	// Best-effort: a failed touch must never fail an authentication that already succeeded.
	_, _ = pool.Exec(ctx, `UPDATE machine_credentials SET last_used_at = now() WHERE principal = $1`,
		principal)
	return p, true
}

// checkMachineTTL enforces the mandatory, bounded life.
func checkMachineTTL(ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("%w: got %s — there is no non-expiring machine credential, because the one "+
			"nobody rotates is the one that never had to be", ErrMachineCredentialExpiry, ttl)
	}
	if ttl > MaxMachineCredentialTTL {
		return fmt.Errorf("%w: got %s, maximum %s", ErrMachineCredentialExpiry, ttl, MaxMachineCredentialTTL)
	}
	return nil
}

// newMachineSecret returns a prefixed token and the hex SHA-256 stored for it.
func newMachineSecret() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("controlplane: generating a machine secret: %w", err)
	}
	secret := MachineTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(secret))
	return secret, hex.EncodeToString(sum[:]), nil
}
