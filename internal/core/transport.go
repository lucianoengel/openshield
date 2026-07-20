package core

import (
	"context"
	"errors"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Transport is the agent↔control-plane boundary.
//
// Note what is absent: there is no method accepting LocalClassification. The
// two-type split in the classification contract is only worth something if the
// transport enforces it — a redaction step at the boundary would be a runtime
// behaviour that can be skipped, whereas a missing method is a compile error.
//
// This interface lives in core and is implemented elsewhere. internal/core must
// never import a broker client: the endpoint pipeline is in-process by
// measurement (T-002), and keeping the dependency out of core is what stops
// that boundary eroding. CI asserts it.
type Transport interface {
	PublishEvent(ctx context.Context, e *corev1.Event) error
	PublishClassification(ctx context.Context, c *corev1.ClassificationSummary) error
	PublishDecision(ctx context.Context, d *corev1.Decision) error
	Close() error
}

// ErrUnreachable means the control plane could not be reached. It is returned,
// never swallowed: a transport that drops a payload silently turns a network
// problem into missing evidence, and missing evidence is indistinguishable from
// "nothing happened".
var ErrUnreachable = errors.New("transport: control plane unreachable")

// ErrPayloadDropped means delivery failed and no durable queue was configured
// to hold the payload.
//
// Offline capability is a stated project principle and is NOT delivered by this
// interface — that is T-024's store-and-forward queue. Until then, callers get
// an error they must handle. The seam is shaped so a durable implementation
// substitutes without changing callers; the guarantee is not yet made.
var ErrPayloadDropped = errors.New("transport: payload not delivered and no durable queue configured")
