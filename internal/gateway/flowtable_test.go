package gateway_test

import (
	"sync"
	"testing"

	"github.com/lucianoengel/openshield/internal/gateway"
)

// A verdict for a registered flow sets its disposition; the default is allow.
func TestTableSetsDisposition(t *testing.T) {
	tbl := gateway.NewTable()
	tbl.Register("f1")
	if tbl.Disposition("f1") != gateway.DispositionAllow {
		t.Fatalf("new flow = %v, want allow", tbl.Disposition("f1"))
	}
	if err := tbl.Block("f1"); err != nil {
		t.Fatal(err)
	}
	if tbl.Disposition("f1") != gateway.DispositionBlock {
		t.Errorf("after Block = %v, want block", tbl.Disposition("f1"))
	}

	tbl.Register("f2")
	if err := tbl.Redirect("f2"); err != nil {
		t.Fatal(err)
	}
	if tbl.Disposition("f2") != gateway.DispositionRedirect {
		t.Errorf("after Redirect = %v, want redirect", tbl.Disposition("f2"))
	}
}

// A verdict for a flow that is not live is an error — not a silent no-op.
func TestTableRefusesUnregisteredFlow(t *testing.T) {
	tbl := gateway.NewTable()
	if err := tbl.Block("ghost"); err == nil {
		t.Error("Block on an unregistered flow returned nil — a verdict for a dead flow is a bug")
	}
	if err := tbl.Redirect("ghost"); err == nil {
		t.Error("Redirect on an unregistered flow returned nil")
	}
}

// Deregister removes the flow; a later verdict for it errors.
func TestTableDeregister(t *testing.T) {
	tbl := gateway.NewTable()
	tbl.Register("f1")
	tbl.Deregister("f1")
	if err := tbl.Block("f1"); err == nil {
		t.Error("Block after Deregister returned nil — the flow is no longer live")
	}
}

// Concurrent flows are isolated: many register/verdict/read cycles race-free.
func TestTableConcurrentFlowsIsolated(t *testing.T) {
	tbl := gateway.NewTable()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		id := "f" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			tbl.Register(id)
			_ = tbl.Block(id)
			if tbl.Disposition(id) != gateway.DispositionBlock {
				t.Errorf("flow %s not block after Block", id)
			}
			tbl.Deregister(id)
		}(id)
	}
	wg.Wait()
}
