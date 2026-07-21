// Package flow enforces network verdicts on live flows, keyed by flow_id.
//
// It is the SECOND enforcement domain after files (encryptlocal, quarantine),
// and it reuses the EXISTING core.TargetedEnforcer interface unchanged: a file
// enforcer resolves a path target to a file; a flow enforcer resolves a flow_id
// target to a live connection (D69). The core interface generalising to a second
// domain with no change is the point.
//
// The live connection does not exist yet (no sockets in N1.1). The enforcer
// therefore resolves the flow_id through a FlowTable seam; the socket-backed
// table that actually drops/resets/redirects a TCP flow is a later increment
// (N1.2). This package proves the enforcement DISPATCH — capability gating and
// target delivery — before any socket exists.
package flow

import (
	"context"
	"fmt"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// FlowTable resolves a flow_id to a live connection and acts on it. The gateway's
// live-connection registry implements this over real sockets (N1.2); the enforcer
// depends only on this seam.
//
// Block-vs-reset (drop silently vs send a TCP RST) is an enforcement MODE the
// table decides, NOT a distinct policy verdict — which is why BLOCK is one action,
// not two (D14/D69).
type FlowTable interface {
	Block(flowID string) error
	Redirect(flowID string) error
}

// Enforcer carries out network verdicts on a flow, resolving the flow_id target
// through a FlowTable.
type Enforcer struct{ table FlowTable }

// Compile-time proof it satisfies the existing targeted interface unchanged.
var _ core.TargetedEnforcer = (*Enforcer)(nil)

func New(t FlowTable) *Enforcer { return &Enforcer{table: t} }

// Capabilities advertises the network verdicts this enforcer can carry out.
func (*Enforcer) Capabilities() []corev1.Action {
	return []corev1.Action{
		corev1.Action_ACTION_BLOCK,
		corev1.Action_ACTION_REDIRECT,
	}
}

// Enforce without a target cannot act: a flow verdict is meaningless without the
// flow to act on. The gateway always supplies the flow_id via EnforceTarget, so
// this path is a misuse and is refused rather than guessed.
func (*Enforcer) Enforce(context.Context, *corev1.Decision) error {
	return fmt.Errorf("flow: enforcement needs a flow_id target — call EnforceTarget")
}

// EnforceTarget carries out the verdict on the flow_id. It rejects any action it
// does not advertise: an unexpected action reaching the enforcer is a
// producer/consumer contract disagreement, not a reason to guess (D14).
func (e *Enforcer) EnforceTarget(_ context.Context, d *corev1.Decision, flowID string) error {
	if flowID == "" {
		return fmt.Errorf("flow: empty flow_id target")
	}
	switch d.GetAction() {
	case corev1.Action_ACTION_BLOCK:
		return e.table.Block(flowID)
	case corev1.Action_ACTION_REDIRECT:
		return e.table.Redirect(flowID)
	default:
		return fmt.Errorf("flow: cannot enforce action %v — flow enforcer carries BLOCK/REDIRECT only", d.GetAction())
	}
}
