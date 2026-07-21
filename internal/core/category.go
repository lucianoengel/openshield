package core

import (
	"context"
	"errors"
)

// Category maps an error to a STABLE slug for structured logging and counting
// (T-028). It matches by error IDENTITY (errors.Is), not by string, so wrapping
// an error with context does not change its category — the category is a property
// of what went wrong, not of how the message was phrased. A log consumer can
// alert on `category=not_recorded` without parsing prose.
//
// A new sentinel needs a line here or it falls through to "unknown"; the test
// pins the known set so an unmapped-but-expected category is caught.
func Category(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrUnreachable):
		return "unreachable"
	case errors.Is(err, ErrNotRecorded):
		return "not_recorded"
	case errors.Is(err, ErrReentry):
		return "reentry"
	case errors.Is(err, ErrNoDecision):
		return "no_decision"
	case errors.Is(err, ErrStageFailed):
		return "stage_failed"
	case errors.Is(err, ErrLedgerUnavailable):
		return "ledger_unavailable"
	case errors.Is(err, ErrAppendFailed):
		return "append_failed"
	case errors.Is(err, ErrContextUnavailable):
		return "context_unavailable"
	default:
		return "unknown"
	}
}
