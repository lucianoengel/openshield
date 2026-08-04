package controlplane

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ONE CANONICAL OPERATOR PRINCIPAL (CONSOLE-1).
//
// Two credential paths reach the operator surface and they used to mint identity strings in two
// different shapes: a client certificate produced `"operator:" + CommonName`, and an OIDC bearer token
// produced the raw `sub`. Nothing reconciled them, and two things went wrong because of it.
//
// FIRST, THE TOKEN PATH REACHED ALMOST NOTHING. `requireTier` authenticated either credential and then
// discarded the identity; eight handlers re-derived it from the TLS peer certificate, which is empty for
// a bearer request. So an SSO operator passed the tier gate and was refused by /alerts/ack,
// /incidents/*, /cases/*, /searches/save, /subject and /view. D373 shipped an authentication method that
// reached almost none of the product.
//
// SECOND — AND THIS IS WHY THE OBVIOUS FIX IS A TRAP — four-eyes is `requester <> approver` over those
// strings. Thread the bearer identity through unchanged and one human requests from the CLI as
// `operator:alice` and approves from the browser as `alice`. The strings differ, the predicate is
// satisfied, and two-person control collapses on case closure, CONTAIN and fleet ENFORCEMENT_DISABLE —
// while the approval row records `strong` assurance (SEC-D), because the deployment genuinely cannot
// tell that those two credentials are one person.
//
// So identity gets a TYPE, not a convention. Every principal is namespaced by the credential that proved
// it, there is exactly one constructor per path, and a bare string cannot be turned into a principal
// outside this file. Namespacing also closes a quieter collision: an identity provider whose subject
// happens to equal a certificate's CommonName would otherwise inherit that certificate's role row.

// principalKind is the credential class that proved a principal. Namespaced because "who is this" is
// only answerable together with "how do we know".
type principalKind string

const (
	// kindCert is a CA-issued operator client certificate.
	kindCert principalKind = "cert"
	// kindOIDC is a verified operator bearer token. Its namespace carries the ISSUER as well as the
	// subject: `sub` is unique only within an issuer, so two identity providers can both mint "alice"
	// and they are not the same person.
	kindOIDC principalKind = "oidc"
	// kindService is a machine principal. It authenticates, and it can never satisfy four-eyes.
	kindService principalKind = "svc"
	// kindPlaybook is the automation engine acting as itself. It predates this vocabulary — a playbook
	// step opens approval requests as `playbook:<name>` — and it is folded in here so that "is this a
	// machine" is one question over one closed set, rather than a prefix check somebody has to remember
	// to extend when a fourth non-human caller appears.
	kindPlaybook principalKind = "playbook"
)

// operatorPrincipal is a verified operator identity, namespaced by how it was proven.
//
// The struct has no exported fields on purpose. A principal that can be constructed field-by-field is a
// principal a handler can invent, and the whole value here is that the only ways to get one are the
// three constructors below and a parse of a string this package previously emitted.
type operatorPrincipal struct {
	kind principalKind
	// issuer is set only for kindOIDC.
	issuer string
	// subject is the CommonName, the token subject, or the service-account name.
	subject string
}

// ErrBadPrincipal means a stored or presented principal string is not in the canonical form.
var ErrBadPrincipal = errors.New("controlplane: not a canonical operator principal")

// certPrincipal builds a principal from a verified client certificate's CommonName.
func certPrincipal(cn string) (operatorPrincipal, error) {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return operatorPrincipal{}, fmt.Errorf("%w: empty certificate CommonName", ErrBadPrincipal)
	}
	if strings.ContainsAny(cn, "#") {
		// '#' separates issuer from subject in the OIDC form. A CommonName containing it could be
		// crafted to parse back as a different principal than it was minted as.
		return operatorPrincipal{}, fmt.Errorf("%w: CommonName contains a reserved character", ErrBadPrincipal)
	}
	return operatorPrincipal{kind: kindCert, subject: cn}, nil
}

// oidcPrincipal builds a principal from a verified token's issuer and subject.
func oidcPrincipal(issuer, sub string) (operatorPrincipal, error) {
	issuer, sub = strings.TrimSpace(issuer), strings.TrimSpace(sub)
	if issuer == "" || sub == "" {
		return operatorPrincipal{}, fmt.Errorf("%w: a token principal needs an issuer and a subject", ErrBadPrincipal)
	}
	if strings.Contains(issuer, "#") {
		return operatorPrincipal{}, fmt.Errorf("%w: issuer contains the reserved separator", ErrBadPrincipal)
	}
	return operatorPrincipal{kind: kindOIDC, issuer: issuer, subject: sub}, nil
}

// servicePrincipal builds a machine principal.
func servicePrincipal(name string) (operatorPrincipal, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return operatorPrincipal{}, fmt.Errorf("%w: a service principal needs a name", ErrBadPrincipal)
	}
	if strings.ContainsAny(name, "#") {
		return operatorPrincipal{}, fmt.Errorf("%w: name contains a reserved character", ErrBadPrincipal)
	}
	return operatorPrincipal{kind: kindService, subject: name}, nil
}

// playbookPrincipal builds the automation engine's own principal.
func playbookPrincipal(name string) (operatorPrincipal, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return operatorPrincipal{}, fmt.Errorf("%w: a playbook principal needs a name", ErrBadPrincipal)
	}
	if strings.ContainsAny(name, "#") {
		return operatorPrincipal{}, fmt.Errorf("%w: name contains a reserved character", ErrBadPrincipal)
	}
	return operatorPrincipal{kind: kindPlaybook, subject: name}, nil
}

// PlaybookPrincipal is the canonical identity string for a named playbook, so the automation engine and
// the approval control agree on one vocabulary.
func PlaybookPrincipal(name string) string {
	p, err := playbookPrincipal(name)
	if err != nil {
		return ""
	}
	return p.String()
}

// String is the canonical stored form: `cert:<cn>`, `oidc:<issuer>#<sub>`, `svc:<name>`,
// `playbook:<name>`.
//
// This is what goes in operator_roles, in an approval's requester and approver, and in every audit row.
// It is stable and parseable, and it can be read by a human looking at a database — which matters,
// because the alternative design (an opaque surrogate id everywhere) makes the audit trail unreadable
// without a join nobody performs at 2am.
func (p operatorPrincipal) String() string {
	if p.kind == "" {
		return ""
	}
	if p.kind == kindOIDC {
		return string(p.kind) + ":" + p.issuer + "#" + p.subject
	}
	return string(p.kind) + ":" + p.subject
}

// valid reports whether this is a real principal rather than the zero value.
func (p operatorPrincipal) valid() bool { return p.kind != "" && p.subject != "" }

// isMachine reports whether this principal is NOT A PERSON — a service account or the automation engine.
//
// Four-eyes consults it, and the asymmetry is the existing spec requirement rather than a new rule:
// automation MAY request an approval (a playbook step opening a wait-for-approval gate is the whole
// point of that step), and may never GRANT one. An approval granted by a machine is a human-in-the-loop
// gate with no human in the loop.
func (p operatorPrincipal) isMachine() bool {
	return p.kind == kindService || p.kind == kindPlaybook
}

// parsePrincipal reads a canonical principal string back.
//
// It is deliberately STRICT: an unnamespaced string — every identity this product stored before
// CONSOLE-1 — is refused rather than guessed at. Guessing is what a migration is for, once, with a
// count reported; doing it per request would mean a legacy string silently resolving to a namespace
// nobody chose, which is the fallback that made the certificate role authoritative for years.
func parsePrincipal(s string) (operatorPrincipal, error) {
	kindStr, rest, found := strings.Cut(strings.TrimSpace(s), ":")
	if !found || rest == "" {
		return operatorPrincipal{}, fmt.Errorf("%w: %q", ErrBadPrincipal, s)
	}
	switch principalKind(kindStr) {
	case kindCert:
		return certPrincipal(rest)
	case kindService:
		return servicePrincipal(rest)
	case kindPlaybook:
		return playbookPrincipal(rest)
	case kindOIDC:
		issuer, sub, ok := strings.Cut(rest, "#")
		if !ok {
			return operatorPrincipal{}, fmt.Errorf("%w: a token principal needs issuer#subject, got %q",
				ErrBadPrincipal, s)
		}
		return oidcPrincipal(issuer, sub)
	default:
		return operatorPrincipal{}, fmt.Errorf("%w: unknown credential kind %q", ErrBadPrincipal, kindStr)
	}
}

// ACCOUNTS: WHICH PRINCIPALS ARE THE SAME PERSON (CONSOLE-1).
//
// Four-eyes is `requester <> approver`, and until this it compared CREDENTIALS. A person holding both a
// certificate and an SSO identity satisfied it alone — request from the CLI, approve from the browser —
// and the two strings differ, so the predicate was happy. Since SEC-D the approval row would then have
// recorded that as `strong` assurance, because the deployment genuinely could not tell.
//
// So the control compares the ACCOUNT. An operator with one credential is their own account and nothing
// changes for them; an operator with two is one person to the control and two rows in the audit trail,
// which is exactly the pair of facts an investigation needs.

// accountFor returns the account a principal belongs to, or the principal itself when it is unlinked.
//
// UNLINKED DEFAULTS TO SELF rather than to an error, because that is the truthful answer: an operator
// nobody has linked to anything is one person with one credential. Failing instead would make four-eyes
// unavailable on every deployment that has not adopted the linking table, which is a control removed by a
// feature nobody asked for.
//
// A database error returns the error rather than falling back to the principal. Falling back would mean a
// database outage silently downgrades four-eyes from comparing people to comparing credentials — the
// fail-open that ZT-7 refused for role resolution, in the one control where it matters most.
func (s *Server) accountFor(ctx context.Context, principal string) (string, error) {
	var account string
	err := s.pool.QueryRow(ctx,
		`SELECT account_id FROM operator_identities WHERE principal = $1`, principal).Scan(&account)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return principal, nil
	case err != nil:
		return "", err
	case strings.TrimSpace(account) == "":
		return principal, nil
	}
	return account, nil
}

// LinkOperatorIdentity records that a principal belongs to an account, so four-eyes treats every
// credential that person holds as one pair of eyes.
func (s *Server) LinkOperatorIdentity(ctx context.Context, principal, accountID, by string) error {
	if _, err := parsePrincipal(principal); err != nil {
		return fmt.Errorf("%w — link `cert:<CommonName>` or `oidc:<issuer>#<subject>`", err)
	}
	if strings.TrimSpace(accountID) == "" {
		return errors.New("controlplane: an identity link needs an account id")
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO operator_identities (principal, account_id, linked_by) VALUES ($1,$2,$3)
		 ON CONFLICT (principal) DO UPDATE SET account_id = EXCLUDED.account_id,
		     linked_at = now(), linked_by = EXCLUDED.linked_by`,
		principal, strings.TrimSpace(accountID), by)
	return err
}

// OperatorAccount reports which account a principal belongs to, for an operator checking their own
// four-eyes wiring before they rely on it.
func (s *Server) OperatorAccount(ctx context.Context, principal string) (string, error) {
	return s.accountFor(ctx, principal)
}
