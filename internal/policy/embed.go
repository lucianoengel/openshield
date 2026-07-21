package policy

import (
	"context"
	_ "embed"
)

//go:embed default.rego
var defaultPolicy string

// DefaultID and DefaultVersion identify the embedded Phase-1 policy. They are
// stamped onto every Decision so the ledger records which policy produced it —
// the precondition for replaying against the right policy.
const (
	DefaultID      = "openshield.default"
	DefaultVersion = "phase1-1"
)

// NewDefault prepares the embedded observe-only policy.
func NewDefault(ctx context.Context) (*Stage, error) {
	return New(ctx, DefaultID, DefaultVersion, defaultPolicy)
}
