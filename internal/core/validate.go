package core

import (
	"errors"
	"fmt"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Validation errors are typed so callers can distinguish "malformed" from
// "rejected on policy grounds" — they have different audit consequences.
var (
	ErrMissingProvenance = errors.New("event: missing provenance field")
	ErrMissingSubject    = errors.New("event: missing subject")
	ErrDirectIdentifier  = errors.New("event: subject must be pseudonymous")
	ErrNoTarget          = errors.New("event: no target set")
	ErrPurposeMismatch   = errors.New("purpose mismatch between event and policy")

	ErrUnspecifiedAction = errors.New("decision: action must not be UNSPECIFIED")
	ErrUnknownAction     = errors.New("decision: unknown action value")
	ErrMissingConfidence = errors.New("decision: confidence is mandatory")
	ErrConfidenceRange   = errors.New("decision: confidence out of range [0,1]")
	ErrMissingPolicy     = errors.New("decision: policy identity required")

	// ErrPathUnavailable is returned rather than an empty string, so a consumer
	// that ignores the distinction fails loudly instead of treating a missing
	// path as an empty one. See docs/spike-t005-fanotify.md — two of the three
	// subject identity forms carry no path at all.
	ErrPathUnavailable = errors.New("event: resolved path not available for this identity form")
)

// IdentityForm names which of the three fanotify subject identities an Event
// carries. Which one arrives follows from the coverage mode the agent selects.
type IdentityForm int

const (
	IdentityNone IdentityForm = iota
	IdentityResolvedPath
	IdentityFileHandle
	IdentityParentAndName
)

func (f IdentityForm) String() string {
	switch f {
	case IdentityResolvedPath:
		return "resolved_path"
	case IdentityFileHandle:
		return "file_handle"
	case IdentityParentAndName:
		return "parent_and_name"
	default:
		return "none"
	}
}

// SubjectIdentityForm reports which identity form a filesystem Event carries.
func SubjectIdentityForm(e *corev1.Event) IdentityForm {
	fs := e.GetFilesystem()
	if fs == nil {
		return IdentityNone
	}
	switch fs.GetIdentity().(type) {
	case *corev1.FilesystemSubject_ResolvedPath:
		return IdentityResolvedPath
	case *corev1.FilesystemSubject_FileHandle:
		return IdentityFileHandle
	case *corev1.FilesystemSubject_ParentAndName:
		return IdentityParentAndName
	default:
		return IdentityNone
	}
}

// ResolvedPath returns the path only when the Event actually carries one.
// It never returns ("", nil) for a missing path — see ErrPathUnavailable.
func ResolvedPath(e *corev1.Event) (string, error) {
	if SubjectIdentityForm(e) != IdentityResolvedPath {
		return "", fmt.Errorf("%w: form=%s", ErrPathUnavailable, SubjectIdentityForm(e))
	}
	return e.GetFilesystem().GetResolvedPath(), nil
}

// ValidateEvent enforces the event-contract spec.
func ValidateEvent(e *corev1.Event) error {
	if e == nil {
		return ErrMissingProvenance
	}
	for name, v := range map[string]string{
		"event_id":     e.GetEventId(),
		"agent_id":     e.GetAgentId(),
		"connector_id": e.GetConnectorId(),
	} {
		if v == "" {
			return fmt.Errorf("%w: %s", ErrMissingProvenance, name)
		}
	}
	if e.GetObservedAt() == nil {
		return fmt.Errorf("%w: observed_at", ErrMissingProvenance)
	}
	// Sequence 0 is permitted (first event); absence cannot be distinguished
	// from zero in proto3 scalars, which is why gap detection is a consumer
	// concern rather than a validation one.
	if e.GetSubject() == nil || e.GetSubject().GetPseudonymousId() == "" {
		return ErrMissingSubject
	}
	if e.GetPurpose() == corev1.Purpose_PURPOSE_UNSPECIFIED {
		return fmt.Errorf("%w: purpose", ErrMissingProvenance)
	}
	if e.GetTarget() == nil {
		return ErrNoTarget
	}
	return nil
}

// CheckPurpose refuses cross-purpose evaluation (D20). Data collected for one
// declared purpose may not be silently reused for another.
func CheckPurpose(e *corev1.Event, policyPurpose corev1.Purpose) error {
	if e.GetPurpose() != policyPurpose {
		return fmt.Errorf("%w: event=%s policy=%s",
			ErrPurposeMismatch, e.GetPurpose(), policyPurpose)
	}
	return nil
}

// knownActions is the closed set. Kept here as well as in the enum so that an
// action added to the proto without being considered here fails validation
// rather than silently becoming valid.
var knownActions = map[corev1.Action]bool{
	corev1.Action_ACTION_ALLOW:            true,
	corev1.Action_ACTION_ALERT:            true,
	corev1.Action_ACTION_BLOCK:            true,
	corev1.Action_ACTION_QUARANTINE_LOCAL: true,
	corev1.Action_ACTION_ENCRYPT_LOCAL:    true,
}

// ValidateDecision enforces the decision-contract spec.
//
// hasConfidence is passed explicitly because proto3 cannot distinguish an
// absent double from 0.0, and the spec requires that a Decision constructed
// without a confidence is rejected rather than defaulted.
func ValidateDecision(d *corev1.Decision, hasConfidence bool) error {
	if d == nil {
		return ErrUnspecifiedAction
	}
	if d.GetAction() == corev1.Action_ACTION_UNSPECIFIED {
		return ErrUnspecifiedAction
	}
	if !knownActions[d.GetAction()] {
		// Explicitly NOT defaulted to ALLOW. An unknown action is a signal that
		// the producer and consumer disagree about the contract, which is a
		// security event, not a reason to permit the operation.
		return fmt.Errorf("%w: %d", ErrUnknownAction, int32(d.GetAction()))
	}
	if !hasConfidence {
		return ErrMissingConfidence
	}
	if c := d.GetConfidence(); c < 0.0 || c > 1.0 {
		return fmt.Errorf("%w: %v", ErrConfidenceRange, c)
	}
	if d.GetPolicyId() == "" || d.GetPolicyVersion() == "" {
		return ErrMissingPolicy
	}
	return nil
}
