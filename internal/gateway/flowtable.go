package gateway

import (
	"fmt"
	"sync"
)

// Disposition is what the connection handler should do with a live flow. It is
// set by the flow enforcer (through the Table) and read by the handler that owns
// the connection — the handler carries it out, so the enforcer never touches the
// socket (which would race the owning handler).
type Disposition int

const (
	// DispositionAllow is the default: the handler forwards the flow. A flow with
	// no verdict — including a BLOCK decision under observe-only, where the
	// enforcer is not registered — stays here (D1).
	DispositionAllow Disposition = iota
	DispositionBlock
	DispositionRedirect
)

func (d Disposition) String() string {
	switch d {
	case DispositionBlock:
		return "block"
	case DispositionRedirect:
		return "redirect"
	default:
		return "allow"
	}
}

// Table is the socket-backed FlowTable: a registry of LIVE flows and the verdict
// to apply to each. It satisfies enforcers/flow.FlowTable, but rather than acting
// on a socket it records a disposition the owning connection handler reads and
// applies. Concurrency-safe: many flows are in flight at once.
type Table struct {
	mu    sync.Mutex
	flows map[string]Disposition
}

func NewTable() *Table { return &Table{flows: map[string]Disposition{}} }

// Register marks a flow as live, at DispositionAllow. The handler calls this before
// running the pipeline, so a verdict has a live flow to land on.
func (t *Table) Register(flowID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flows[flowID] = DispositionAllow
}

// Deregister removes a flow once the handler is done with it.
func (t *Table) Deregister(flowID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.flows, flowID)
}

// Disposition reports the verdict recorded for a live flow (allow if none).
func (t *Table) Disposition(flowID string) Disposition {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.flows[flowID]
}

// Block sets a live flow's disposition to block. A verdict for a flow that is not
// live is an error — a verdict for an unknown flow is a bug, surfaced not
// swallowed (the gateway audits the enforcement failure).
func (t *Table) Block(flowID string) error { return t.set(flowID, DispositionBlock) }

// Redirect sets a live flow's disposition to redirect.
func (t *Table) Redirect(flowID string) error { return t.set(flowID, DispositionRedirect) }

func (t *Table) set(flowID string, d Disposition) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.flows[flowID]; !ok {
		return fmt.Errorf("flowtable: verdict for unregistered flow %q — not a live flow", flowID)
	}
	t.flows[flowID] = d
	return nil
}
