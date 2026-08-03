package controlplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lucianoengel/openshield/internal/notify"
)

// Four-eyes approvals (SOAR-3), generalized from D36's case-close control.
//
// The rule is one line and the entire point: an approval must come from an operator DIFFERENT from the one
// who requested it. What makes it a CONTROL rather than a check is where that comparison lives — inside the
// UPDATE predicate, so two operators racing cannot both succeed. Moving it into Go would reintroduce
// exactly the race the original implementation got right.
//
// Subjects are (kind, id) pairs opaque to this package: a response-intent id and a playbook-step id do not
// live in one table, and a nullable foreign key per consumer is how the original got welded into `cases`.
const (
	ApprovalSubjectCaseClose      = "case-close"
	ApprovalSubjectPlaybookStep   = "playbook-step"
	ApprovalSubjectResponseIntent = "response-intent"
)

// Approval states.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalExpired  = "expired"
)

var (
	// ErrApprovalNotPending means the request was already resolved (or never existed as pending). An
	// outcome is terminal: re-approving a decided request would erase who decided it.
	ErrApprovalNotPending = errors.New("controlplane: approval is not pending")
	// ErrApprovalExpired means the TTL elapsed. A week-old request is not consent.
	ErrApprovalExpired = errors.New("controlplane: approval request has expired")
	// ErrApprovalNotFound means no such approval.
	ErrApprovalNotFound = errors.New("controlplane: approval not found")
)

// Approval is one request for a second pair of eyes.
type Approval struct {
	ID          int64      `json:"id"`
	SubjectKind string     `json:"subject_kind"`
	SubjectID   string     `json:"subject_id"`
	State       string     `json:"state"`
	Requester   string     `json:"requester"`
	Approver    string     `json:"approver,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	RequestedAt time.Time  `json:"requested_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
	ExpiresAt   time.Time  `json:"expires_at"`
	// Assurance is what four-eyes was worth on this deployment when this approval was RESOLVED
	// (SEC-D): "strong", "weak", or empty for a row resolved before it was recorded. It is a fact about
	// that moment, not about the configuration a reader happens to have now.
	Assurance string `json:"assurance,omitempty"`
}

// DefaultApprovalTTL bounds how long a request stays live.
const DefaultApprovalTTL = 4 * time.Hour

// RequestApproval opens a four-eyes request for a subject.
func (s *Server) RequestApproval(ctx context.Context, kind, subjectID, requester, reason string, ttl time.Duration) (int64, error) {
	if requester == "" {
		return 0, ErrNoViewer
	}
	if kind == "" || subjectID == "" {
		return 0, errors.New("controlplane: an approval needs a subject kind and id")
	}
	if ttl <= 0 {
		ttl = DefaultApprovalTTL
	}
	// THE ACCOUNT IS RESOLVED AT REQUEST TIME AND STORED (CONSOLE-1). Four-eyes compares people, and the
	// requester's credential is only one of possibly several a person holds.
	requesterAccount, aerr := s.accountFor(ctx, requester)
	if aerr != nil {
		// Not a fallback to the raw principal: that would downgrade the comparison from people to
		// credentials exactly when the linking table is unreadable, which is a fail-open on the control
		// this table exists to make real.
		return 0, fmt.Errorf("controlplane: resolving the requester's account: %w", aerr)
	}
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO approvals (subject_kind, subject_id, requester, requester_account, reason, expires_at)
		 VALUES ($1,$2,$3,$4,$5, now() + $6::interval) RETURNING id`,
		kind, subjectID, requester, requesterAccount, reason,
		fmt.Sprintf("%d seconds", int(ttl.Seconds()))).Scan(&id)
	if err != nil {
		return 0, err
	}
	// SOAR-9: TELL SOMEONE. Until this, a four-eyes request waited on a human who was never informed —
	// and SOAR-4's wait-for-approval step parked a run indefinitely on a decision nobody knew was
	// pending, which is the difference between a control and a deadlock.
	//
	// Best-effort and off the write path (emit queues; a nil/absent sink is a no-op): the approvals ROW
	// is the record, delivery is an additive copy, so a failing sink must never fail the request.
	//
	// The requester's free-text REASON is deliberately not carried in a field routing matches on —
	// routing decides on a closed vocabulary, and matching on free text would make the routing decision
	// depend on what a requester typed.
	s.emit(ctx, notify.Notification{
		Kind:     notify.KindApprovalPending,
		Subject:  subjectID,
		Severity: SeverityHigh,
		At:       s.now(),
		ID:       fmt.Sprintf("approval_%d", id),
		Detail:   fmt.Sprintf("approval %d pending: %s %s (requested by %s)", id, kind, subjectID, requester),
	})
	return id, nil
}

// ResolveApproval approves or denies a pending request.
//
// EVERY condition — still pending, not expired, approver≠requester — is in the UPDATE predicate, so the
// resolution is atomic. The follow-up read exists only to say WHICH condition failed; it is never what
// decides.
func (s *Server) ResolveApproval(ctx context.Context, id int64, approver string, approve bool) error {
	if approver == "" {
		return ErrNoViewer
	}
	// SEC-D: what a second pair of eyes is WORTH here, decided now and written down.
	//
	// Only an APPROVAL is gated. A denial on a weak deployment must still land: refusing to record "no"
	// because the identity model is not hardened would leave a pending high-impact request alive and
	// approvable, which turns a hardening control into a way of keeping dangerous things pending.
	assurance := AssessFourEyes()
	if approve && !assurance.Strong() && RequireStrongFourEyes() {
		return fmt.Errorf("%w: %s", ErrWeakFourEyes, strings.Join(assurance.Gaps, "; "))
	}
	// THE COMPARISON IS ON THE ACCOUNT, NOT THE CREDENTIAL STRING (CONSOLE-1).
	//
	// One human holding a certificate and an SSO login presents two different principals, and comparing
	// those strings is satisfied by one person acting twice. The credential is still RECORDED — "alice
	// approved it from a browser session" is a different fact from "alice approved it", and an
	// investigation needs the second one — but it is not what the control compares.
	//
	// Still inside the UPDATE predicate, which is the property that made this a control rather than a
	// check: two operators racing cannot both succeed, and moving the comparison into Go would
	// reintroduce exactly the race the original got right.
	approverAccount, aerr := s.accountFor(ctx, approver)
	if aerr != nil {
		return fmt.Errorf("controlplane: resolving the approver's account: %w", aerr)
	}
	state := ApprovalDenied
	if approve {
		state = ApprovalApproved
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE approvals SET state = $1, approver = $2, approver_account = $5, resolved_at = now(),
		        assurance = $4
		  WHERE id = $3 AND state = 'pending' AND expires_at > now() AND requester_account <> $5`,
		state, approver, id, assurance.Level, approverAccount)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Nothing moved — report which rule refused it.
	var cur, requesterAccount string
	var expires time.Time
	if err := s.pool.QueryRow(ctx,
		`SELECT state, requester_account, expires_at FROM approvals WHERE id = $1`, id).
		Scan(&cur, &requesterAccount, &expires); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrApprovalNotFound
		}
		return err
	}
	switch {
	case cur != ApprovalPending:
		return fmt.Errorf("%w: already %s", ErrApprovalNotPending, cur)
	case !expires.After(time.Now()):
		return ErrApprovalExpired
	case requesterAccount == approverAccount:
		// The security case, reported as the existing four-eyes error so callers keep one sentinel. It
		// now also catches the case that motivated CONSOLE-1: two DIFFERENT credentials belonging to one
		// person, which the old string comparison waved through.
		return ErrFourEyes
	default:
		return ErrApprovalNotPending
	}
}

// ApprovalFor returns the most recent approval for a subject, so a consumer can check its own decision.
// An approval for one subject can never satisfy another: the lookup is keyed by both parts.
func (s *Server) ApprovalFor(ctx context.Context, kind, subjectID string) (*Approval, error) {
	var a Approval
	var approver, reason *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, subject_kind, subject_id, state, requester, approver, reason, requested_at, resolved_at, expires_at, assurance
		   FROM approvals WHERE subject_kind=$1 AND subject_id=$2 ORDER BY id DESC LIMIT 1`, kind, subjectID).
		Scan(&a.ID, &a.SubjectKind, &a.SubjectID, &a.State, &a.Requester, &approver, &reason,
			&a.RequestedAt, &a.ResolvedAt, &a.ExpiresAt, &a.Assurance)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrApprovalNotFound
	}
	if err != nil {
		return nil, err
	}
	if approver != nil {
		a.Approver = *approver
	}
	if reason != nil {
		a.Reason = *reason
	}
	// A pending request past its TTL is reported as expired even before the sweeper relabels it, so a
	// consumer reading this never sees a dead request as live.
	if a.State == ApprovalPending && !a.ExpiresAt.After(time.Now()) {
		a.State = ApprovalExpired
	}
	return &a, nil
}

// ExpirePendingApprovals relabels timed-out requests so an operator's queue does not show dead ones as
// live. It is COSMETIC, not load-bearing: expiry is already enforced in ResolveApproval's predicate, so
// even if this never ran, an expired request could not be approved.
func (s *Server) ExpirePendingApprovals(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE approvals SET state = 'expired', resolved_at = now()
		  WHERE state = 'pending' AND expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
