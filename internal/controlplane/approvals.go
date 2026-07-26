package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO approvals (subject_kind, subject_id, requester, reason, expires_at)
		 VALUES ($1,$2,$3,$4, now() + $5::interval) RETURNING id`,
		kind, subjectID, requester, reason, fmt.Sprintf("%d seconds", int(ttl.Seconds()))).Scan(&id)
	if err != nil {
		return 0, err
	}
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
	state := ApprovalDenied
	if approve {
		state = ApprovalApproved
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE approvals SET state = $1, approver = $2, resolved_at = now()
		  WHERE id = $3 AND state = 'pending' AND expires_at > now() AND requester <> $2`,
		state, approver, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Nothing moved — report which rule refused it.
	var cur, requester string
	var expires time.Time
	if err := s.pool.QueryRow(ctx,
		`SELECT state, requester, expires_at FROM approvals WHERE id = $1`, id).Scan(&cur, &requester, &expires); err != nil {
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
	case requester == approver:
		// The security case, reported as the existing four-eyes error so callers keep one sentinel.
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
		`SELECT id, subject_kind, subject_id, state, requester, approver, reason, requested_at, resolved_at, expires_at
		   FROM approvals WHERE subject_kind=$1 AND subject_id=$2 ORDER BY id DESC LIMIT 1`, kind, subjectID).
		Scan(&a.ID, &a.SubjectKind, &a.SubjectID, &a.State, &a.Requester, &approver, &reason,
			&a.RequestedAt, &a.ResolvedAt, &a.ExpiresAt)
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
