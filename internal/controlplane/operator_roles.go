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

// certCommonName returns the verified peer certificate's CommonName, or "" when there is no verified
// peer. It is a raw name, NOT an identity: turning it into one is certPrincipal's job, and keeping the
// two apart is what stops a bare string being used where a principal is meant.
func certCommonName(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

// resolveOperatorRole returns the role in force for a verified certificate, right now.
//
// The order is the whole point: the DATABASE decides, and the certificate is consulted only when the
// database has nothing to say about this identity.
func (s *Server) resolveOperatorRole(ctx context.Context, auth operatorAuth) (operatorGrant, operatorRoleSource) {
	if !auth.ok || !auth.principal.valid() {
		return operatorGrant{}, roleAbsent
	}
	identity := auth.principal.String()
	grant, revoked, err := s.lookupOperatorRole(ctx, identity)
	switch {
	case err == nil && revoked:
		// An explicit revocation OUTRANKS the certificate. Returning the cert's role here would mean
		// revoking someone restored whatever their certificate said.
		return operatorGrant{}, roleRevoked
	case err == nil:
		return grant, roleFromDatabase
	case !errors.Is(err, pgx.ErrNoRows):
		// A database error must NOT fall through to the certificate: that would turn a database outage into
		// a silent restoration of stale privileges — a fail-open on authorization, which is the one place
		// this project never fails open.
		return operatorGrant{}, roleAbsent
	}
	if strictOperatorRoles() {
		return operatorGrant{}, roleAbsent
	}
	// NO CERTIFICATE MEANS NO FALLBACK. An SSO operator has no embedded role to fall back TO, so they are
	// strict by construction: no record, no access, whatever the token asserts. The fallback exists to keep
	// existing certificate holders working through the migration and for nothing else.
	if auth.certState == nil {
		return operatorGrant{}, roleAbsent
	}
	// TIER ONLY. The certificate cannot carry the privacy authority (CONSOLE-1) — `certRole` does not
	// recognise `privacy-officer`, and the grant built here leaves Privacy false whatever the OU says.
	// The fallback exists to keep existing certificate holders working, and it must never be able to
	// grant MORE than the recorded grant it stands in for.
	return operatorGrant{Tier: certRole(auth.certState)}, roleFromCertificate
}

// lookupOperatorRole reads one identity's row.
func (s *Server) lookupOperatorRole(ctx context.Context, identity string) (operatorGrant, bool, error) {
	s.mu.Lock()
	pool := s.pool
	s.mu.Unlock()
	if pool == nil {
		return operatorGrant{}, false, pgx.ErrNoRows
	}
	var g operatorGrant
	var revoked bool
	err := pool.QueryRow(ctx,
		`SELECT role, privacy_officer, revoked FROM operator_roles WHERE identity = $1`, identity).
		Scan(&g.Tier, &g.Privacy, &revoked)
	return g, revoked, err
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

// SetOperatorRole grants or changes an operator's grant. Takes effect on the next request.
//
// `role` is a grant SPECIFICATION (CONSOLE-1): a tier, `privacy-officer`, or both separated by a comma.
// The whole grant is replaced, which is what makes `operator-role set cert:alice admin` the way to take
// the privacy authority back off an administrator the upgrade granted both to. A merge would have no
// such inverse — an authority that can only ever be added is not one that can be separated.
func (s *Server) SetOperatorRole(ctx context.Context, identity, role, by string) error {
	grant, gerr := parseGrant(role)
	if gerr != nil {
		return gerr
	}
	// THE IDENTITY MUST BE A CANONICAL PRINCIPAL (CONSOLE-1).
	//
	// A bare name is refused rather than defaulted to a namespace. Defaulting is how a grant meant for a
	// certificate holder would silently also cover whoever an identity provider calls by the same name —
	// and the namespace is the only thing keeping those apart.
	p, perr := parsePrincipal(identity)
	if perr != nil {
		return fmt.Errorf("%w — grant to `cert:<CommonName>` or `oidc:<issuer>#<subject>`", perr)
	}
	// STORED IN CANONICAL FORM, not as the caller spelled it. The lookup key is built by String(), so a
	// grant stored verbatim would silently miss for any input that parses to the same principal without
	// being byte-identical to it — surrounding whitespace being the obvious one.
	identity = p.String()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO operator_roles (identity, role, privacy_officer, revoked, updated_at, updated_by)
		 VALUES ($1,$2,$3,false,now(),$4)
		 ON CONFLICT (identity) DO UPDATE SET role = EXCLUDED.role,
		     privacy_officer = EXCLUDED.privacy_officer, revoked = false,
		     updated_at = now(), updated_by = EXCLUDED.updated_by`,
		identity, grant.Tier, grant.Privacy, by)
	return err
}

// RevokeOperator removes an operator's access immediately.
//
// A ROW, NOT A DELETE: deleting would fall back to the certificate's embedded role, so "revoke" would
// restore whatever the certificate said. That reversal is the reason this is written down rather than left
// to whoever next edits this file.
func (s *Server) RevokeOperator(ctx context.Context, identity, by string) error {
	// Canonicalised like the grant path: a revocation that writes a differently-spelled key creates a
	// second row and revokes nobody, which is the worst possible outcome for this particular call.
	p, perr := parsePrincipal(identity)
	if perr != nil {
		return fmt.Errorf("%w — revoke `cert:<CommonName>` or `oidc:<issuer>#<subject>`", perr)
	}
	identity = p.String()
	// The privacy authority is cleared alongside the tier. A revoked row that still reads
	// `privacy-officer` in `operator-role list` describes an access this identity does not have, and the
	// listing is what an access review reads.
	_, err := s.pool.Exec(ctx,
		`INSERT INTO operator_roles (identity, role, privacy_officer, revoked, updated_at, updated_by)
		 VALUES ($1,'',false,true,now(),$2)
		 ON CONFLICT (identity) DO UPDATE SET revoked = true, privacy_officer = false, updated_at = now(),
		     updated_by = EXCLUDED.updated_by`,
		identity, by)
	return err
}

// operatorRoleChanges counts authorization changes, so a spike is visible without reading the table.
var operatorRoleChanges atomic.Int64

// OperatorRoleChanges reports how many role grants/revocations this process has applied.
func OperatorRoleChanges() int64 { return operatorRoleChanges.Load() }

// OperatorRoleRow is one row of the operator authorization table, for `operator-role list`.
type OperatorRoleRow struct {
	Identity string
	// Role is the WHOLE grant in the form `operator-role set` accepts — `admin`, `privacy-officer`, or
	// `admin,privacy-officer` — not just the tier. An access review reads this listing, and a listing
	// that omits an axis of authority is a review that cannot see it.
	Role      string
	Revoked   bool
	UpdatedAt time.Time
	UpdatedBy string
}

// ListOperatorRoles returns every operator row, revoked ones included — a revocation is a fact an operator
// reviewing access needs to see, not an absence to infer.
func (s *Server) ListOperatorRoles(ctx context.Context) ([]OperatorRoleRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT identity, role, privacy_officer, revoked, updated_at, updated_by
		   FROM operator_roles ORDER BY identity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OperatorRoleRow
	for rows.Next() {
		var r OperatorRoleRow
		var g operatorGrant
		if err := rows.Scan(&r.Identity, &g.Tier, &g.Privacy, &r.Revoked, &r.UpdatedAt,
			&r.UpdatedBy); err != nil {
			return nil, err
		}
		r.Role = g.String()
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
	// Issuer is who minted the token. Part of the interface because a subject is unique only within an
	// issuer, so a principal that omits it is not an identity — it is a name two providers can both use.
	Issuer() string
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
	// principal is the canonical, namespaced identity (CONSOLE-1). It replaces a bare string that meant
	// `operator:<CN>` from one credential path and a raw `sub` from the other.
	principal operatorPrincipal
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
		if cn := certCommonName(r.TLS); cn != "" {
			p, err := certPrincipal(cn)
			if err != nil {
				// A CommonName that cannot become a canonical principal authenticates NOTHING. It is a
				// CA-issuance problem, and accepting it would mean storing an identity that parses back
				// as something else.
				return operatorAuth{}
			}
			return operatorAuth{principal: p, certState: r.TLS, ok: true}
		}
	}
	tok := bearerToken(r)
	if tok == "" {
		return operatorAuth{}
	}
	// A MACHINE TOKEN IS DECIDED BY ITS PREFIX, BEFORE THE IDENTITY PROVIDER IS CONSULTED (CONSOLE-1).
	//
	// Both credential classes arrive on the same header, so something has to choose. Handing a machine
	// token to the OIDC verifier would fail there with a message about the identity provider and send
	// whoever debugs it to the wrong system; worse, a deployment with SSO unconfigured would refuse a
	// perfectly valid machine credential for the unrelated reason that there is no verifier.
	//
	// It carries NO certState, so there is no legacy fallback: a machine with no recorded grant is
	// authorized for nothing, whatever its credential proves.
	if strings.HasPrefix(tok, MachineTokenPrefix) {
		if p, ok := s.authenticateMachine(r.Context(), tok); ok {
			return operatorAuth{principal: p, ok: true}
		}
		// A token that LOOKS like ours and does not verify is refused here rather than falling through
		// to the identity provider. Falling through would let an expired or revoked machine credential
		// get a second opinion from a system that knows nothing about it.
		return operatorAuth{}
	}
	v := s.operatorOIDCVerifier()
	if v == nil {
		return operatorAuth{}
	}
	sub, err := v.VerifySubjectWithProof(tok, r.Header.Get("DPoP"), r.Method, requestURI(r),
		requireBoundOperatorTokens())
	if err != nil || sub == "" {
		// A token that does not verify is NOT an identity. No partial credit, no defaulting to anonymous
		// with a lower tier — every check in the verifier is fail-closed and so is this.
		return operatorAuth{}
	}
	// THE ISSUER IS PART OF THE IDENTITY. `sub` is unique only within an issuer, so two identity
	// providers can both mint "alice" and they are not the same person — and without the issuer in the
	// key, a subject equal to a certificate CommonName would inherit that certificate's role row.
	p, perr := oidcPrincipal(v.Issuer(), sub)
	if perr != nil {
		return operatorAuth{}
	}
	return operatorAuth{principal: p, ok: true}
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
	p, perr := parsePrincipal(identity)
	if perr != nil {
		return perr
	}
	identity = p.String()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO operator_roles (identity, role, privacy_officer, revoked, updated_at, updated_by)
		 VALUES ($1,'',false,false,now(),$2)
		 ON CONFLICT (identity) DO UPDATE SET revoked = false, updated_at = now(),
		     updated_by = EXCLUDED.updated_by`,
		identity, by)
	return err
}
