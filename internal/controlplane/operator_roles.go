package controlplane

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// ZT-7: THE ROLE LEAVES THE CERTIFICATE.
//
// It used to be stamped into the leaf's Subject OU and read from there on every request, so authorization
// was frozen for the certificate's lifetime — a demotion or a removal did not take effect until the
// certificate expired. There was no primitive for "revoke this operator's responder rights now".
//
// The certificate still AUTHENTICATES (CommonName says who). This table says what they may do, NOW.
//
// # NO CACHE, DELIBERATELY
//
// One database lookup per authorized request. Caching it would reintroduce exactly the staleness this
// exists to remove, just with a shorter and less predictable window — and "the revocation takes effect
// within the cache TTL" is the sentence that makes a security control untrustworthy. The operator API is
// low-volume by nature (humans and their tools, not the fleet), so the cost is a primary-key lookup on a
// connection that is already open.
//
// # THE LEGACY FALLBACK, AND WHY IT IS NOT THE DEFAULT FOREVER
//
// Every operator certificate already issued carries a role in its OU. Switching to database-only
// authorization in one step would lock every existing deployment out of its own control plane, including
// the admin who would have to fix it. So an identity with NO ROW falls back to its certificate's role and
// is LOGGED as doing so, once, with the command to fix it.
//
// That fallback still fixes the defect for anyone who uses the table: adding a row is immediate, and a row
// always beats the certificate — including a row that says `revoked`. What it does not do is deny by
// default, and OPENSHIELD_OPERATOR_ROLES_STRICT=1 turns it off for a deployment that has finished
// migrating. The intended end state is strict; the migration path is why it is not the default yet.

// operatorRoleSource says where an authorization decision came from, so the caller can log a legacy
// fallback without re-deriving it.
type operatorRoleSource int

const (
	roleFromDatabase operatorRoleSource = iota
	roleFromCertificate
	roleRevoked
	roleAbsent
)

// legacyRoleWarned tracks identities already warned about, so a legacy operator generates one line rather
// than one per request. A warning that repeats per request is a warning people filter out.
var legacyRoleWarned sync.Map

// strictOperatorRoles reports whether a certificate-embedded role is refused outright.
func strictOperatorRoles() bool {
	return strings.TrimSpace(os.Getenv("OPENSHIELD_OPERATOR_ROLES_STRICT")) == "1"
}

// certIdentity returns the verified peer certificate's CommonName, or "" when there is no verified peer.
func certIdentity(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

// resolveOperatorRole returns the role in force for a verified certificate, right now.
//
// The order is the whole point: the DATABASE decides, and the certificate is consulted only when the
// database has nothing to say about this identity.
func (s *Server) resolveOperatorRole(ctx context.Context, auth operatorAuth) (string, operatorRoleSource) {
	if !auth.ok || auth.identity == "" {
		return "", roleAbsent
	}
	identity := auth.identity
	role, revoked, err := s.lookupOperatorRole(ctx, identity)
	switch {
	case err == nil && revoked:
		// An explicit revocation OUTRANKS the certificate. Returning the cert's role here would mean
		// revoking someone restored whatever their certificate said.
		return "", roleRevoked
	case err == nil:
		return role, roleFromDatabase
	case !errors.Is(err, pgx.ErrNoRows):
		// A database error must NOT fall through to the certificate: that would turn a database outage into
		// a silent restoration of stale privileges — a fail-open on authorization, which is the one place
		// this project never fails open.
		return "", roleAbsent
	}
	if strictOperatorRoles() {
		return "", roleAbsent
	}
	// NO CERTIFICATE MEANS NO FALLBACK. An SSO operator has no embedded role to fall back TO, so they are
	// strict by construction: no record, no access, whatever the token asserts. The fallback exists to keep
	// existing certificate holders working through the migration and for nothing else.
	if auth.certState == nil {
		return "", roleAbsent
	}
	return certRole(auth.certState), roleFromCertificate
}

// lookupOperatorRole reads one identity's row.
func (s *Server) lookupOperatorRole(ctx context.Context, identity string) (string, bool, error) {
	s.mu.Lock()
	pool := s.pool
	s.mu.Unlock()
	if pool == nil {
		return "", false, pgx.ErrNoRows
	}
	var role string
	var revoked bool
	err := pool.QueryRow(ctx,
		`SELECT role, revoked FROM operator_roles WHERE identity = $1`, identity).Scan(&role, &revoked)
	return role, revoked, err
}

// warnLegacyRole reports, once per identity, that an operator is running on a role embedded in their
// certificate — which cannot be changed without reissuing it.
func (s *Server) warnLegacyRole(identity, role string) {
	if _, seen := legacyRoleWarned.LoadOrStore(identity, true); seen {
		return
	}
	fmt.Fprintf(os.Stderr, "openshield-server: operator %q is authorized as %q FROM ITS CERTIFICATE — that "+
		"role cannot be changed or revoked without reissuing the certificate. Record it server-side with "+
		"`openshield-server operator-role set %s %s`, then set OPENSHIELD_OPERATOR_ROLES_STRICT=1 once every "+
		"operator has a row.\n", identity, role, identity, role)
}

// SetOperatorRole grants or changes an operator's role. Takes effect on the next request.
func (s *Server) SetOperatorRole(ctx context.Context, identity, role, by string) error {
	if !validOperatorRole(role) {
		return fmt.Errorf("controlplane: %q is not an operator role (want analyst, responder or admin)", role)
	}
	if strings.TrimSpace(identity) == "" {
		return errors.New("controlplane: no identity")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO operator_roles (identity, role, revoked, updated_at, updated_by)
		 VALUES ($1,$2,false,now(),$3)
		 ON CONFLICT (identity) DO UPDATE SET role = EXCLUDED.role, revoked = false,
		     updated_at = now(), updated_by = EXCLUDED.updated_by`,
		identity, role, by)
	return err
}

// RevokeOperator removes an operator's access immediately.
//
// A ROW, NOT A DELETE: deleting would fall back to the certificate's embedded role, so "revoke" would
// restore whatever the certificate said. That reversal is the reason this is written down rather than left
// to whoever next edits this file.
func (s *Server) RevokeOperator(ctx context.Context, identity, by string) error {
	if strings.TrimSpace(identity) == "" {
		return errors.New("controlplane: no identity")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO operator_roles (identity, role, revoked, updated_at, updated_by)
		 VALUES ($1,'',true,now(),$2)
		 ON CONFLICT (identity) DO UPDATE SET revoked = true, updated_at = now(),
		     updated_by = EXCLUDED.updated_by`,
		identity, by)
	return err
}

// validOperatorRole is the closed set an operator row may hold. `agent` is deliberately absent: an agent is
// not an operator, and letting one be granted an operator tier here would turn a fleet credential into a
// console credential.
func validOperatorRole(role string) bool {
	switch role {
	case RoleAnalyst, RoleResponder, RoleAdmin:
		return true
	}
	return false
}

// operatorRoleChanges counts authorization changes, so a spike is visible without reading the table.
var operatorRoleChanges atomic.Int64

// OperatorRoleChanges reports how many role grants/revocations this process has applied.
func OperatorRoleChanges() int64 { return operatorRoleChanges.Load() }

// OperatorRoleRow is one row of the operator authorization table, for `operator-role list`.
type OperatorRoleRow struct {
	Identity  string
	Role      string
	Revoked   bool
	UpdatedAt time.Time
	UpdatedBy string
}

// ListOperatorRoles returns every operator row, revoked ones included — a revocation is a fact an operator
// reviewing access needs to see, not an absence to infer.
func (s *Server) ListOperatorRoles(ctx context.Context) ([]OperatorRoleRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT identity, role, revoked, updated_at, updated_by FROM operator_roles ORDER BY identity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OperatorRoleRow
	for rows.Next() {
		var r OperatorRoleRow
		if err := rows.Scan(&r.Identity, &r.Role, &r.Revoked, &r.UpdatedAt, &r.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ZT-7 (second half): OPERATOR SSO.
//
// An operator may authenticate with an OIDC bearer token instead of a client certificate. Both paths
// converge on the SAME authorization: the credential says who, `operator_roles` says what they may do.
//
// THE TOKEN'S CLAIMS DO NOT DECIDE THE ROLE, and that is the whole design. Mapping an IdP group claim to a
// tier is the conventional shape and it reintroduces the defect the first half of ZT-7 removed — a token
// issued before a demotion still asserts the old group until it expires. Shorter fuse than a certificate,
// same failure. So the IdP is an identity provider here and nothing more.
//
// A CONSEQUENCE WORTH NAMING: an SSO operator has no certificate, so there is no embedded role to fall back
// to. They are STRICT by construction — no record means no access, whatever the token says. The legacy
// fallback exists only for certificate holders, and only until a deployment sets strict mode.

// operatorTokenVerifier is the slice of the OIDC verifier this needs, as an interface so the control plane
// does not depend on the gateway's package and so a test can supply a stub.
//
// The proof-aware signature is the ONLY one, deliberately. Keeping a plain VerifySubject alongside it would
// leave a path that ignores sender-constraining, and the whole value of DPoP is that there is no such path.
type operatorTokenVerifier interface {
	VerifySubjectWithProof(token, dpopProof, method, requestURI string, requireBound bool) (string, error)
}

// requireBoundOperatorTokens reports whether an operator token that is NOT sender-constrained is refused.
//
// Off by default and documented as the hardened end state, the same shape as OPENSHIELD_OPERATOR_ROLES_STRICT:
// turning it on before the identity provider issues bound tokens locks every operator out.
func requireBoundOperatorTokens() bool {
	return strings.TrimSpace(os.Getenv("OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP")) == "1"
}

// requestURI reconstructs the absolute URI a DPoP proof must be bound to (htu).
//
// Scheme is https unconditionally: the operator surface is served over TLS, and deriving it from a header a
// client controls would let that client choose what its own proof has to match.
func requestURI(r *http.Request) string {
	return "https://" + r.Host + r.URL.Path
}

// SetOperatorOIDC installs the verifier for operator bearer tokens. Nil disables SSO, which is the default:
// an unconfigured deployment accepts client certificates only.
func (s *Server) SetOperatorOIDC(v operatorTokenVerifier) {
	s.mu.Lock()
	s.operatorOIDC = v
	s.mu.Unlock()
}

func (s *Server) operatorOIDCVerifier() operatorTokenVerifier {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.operatorOIDC
}

// bearerToken extracts a bearer credential, case-insensitively per RFC 7235.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// operatorAuth is the result of authenticating a request, before any authorization decision.
type operatorAuth struct {
	identity string
	// certState is non-nil only for a certificate-authenticated operator; it is what the legacy fallback
	// reads. A bearer-authenticated operator has none, and therefore no fallback.
	certState *tls.ConnectionState
	ok        bool
}

// authenticateOperator resolves WHO is calling, from a client certificate or a bearer token.
//
// THE CERTIFICATE WINS when both are present. A request carrying both is ambiguous, and resolving ambiguity
// toward the credential that was verified by the TLS stack — rather than one parsed from a header — is the
// conservative direction.
func (s *Server) authenticateOperator(r *http.Request) operatorAuth {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if id := certIdentity(r.TLS); id != "" {
			return operatorAuth{identity: id, certState: r.TLS, ok: true}
		}
	}
	v := s.operatorOIDCVerifier()
	if v == nil {
		return operatorAuth{}
	}
	tok := bearerToken(r)
	if tok == "" {
		return operatorAuth{}
	}
	sub, err := v.VerifySubjectWithProof(tok, r.Header.Get("DPoP"), r.Method, requestURI(r),
		requireBoundOperatorTokens())
	if err != nil || sub == "" {
		// A token that does not verify is NOT an identity. No partial credit, no defaulting to anonymous
		// with a lower tier — every check in the verifier is fail-closed and so is this.
		return operatorAuth{}
	}
	return operatorAuth{identity: sub, ok: true}
}

// recordOperatorIdentity notes that an identity EXISTS, without granting it anything.
//
// Used by SCIM provisioning. The empty role is the point: `roleRank("")` is 0, so the operator is
// authorized for nothing until an administrator grants a tier. Recording them anyway is what makes them
// visible to `operator-role list` and what lets a later revocation be an UPDATE rather than an insert of a
// row nobody expected.
//
// An existing row is left alone apart from clearing a revocation — re-provisioning must not silently
// downgrade someone who already has a tier.
func (s *Server) recordOperatorIdentity(ctx context.Context, identity, by string) error {
	if strings.TrimSpace(identity) == "" {
		return errors.New("controlplane: no identity")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO operator_roles (identity, role, revoked, updated_at, updated_by)
		 VALUES ($1,'',false,now(),$2)
		 ON CONFLICT (identity) DO UPDATE SET revoked = false, updated_at = now(),
		     updated_by = EXCLUDED.updated_by`,
		identity, by)
	return err
}
