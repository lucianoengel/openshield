package gateway_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The gateway is network-capable, so it MUST NOT link the parser: body
// classification runs in the sandboxed worker (D72), and a parser bug in the
// network process is the RCE this split removes. This is the check-agent-deps
// discipline applied to the gateway — asserted against the real dependency graph,
// not by reading the imports, because a transitive pull-in would slip past a grep.
func TestGatewayDoesNotLinkTheParser(t *testing.T) {
	// The library package AND the binary must both exclude the parser: the binary
	// spawns the worker (D72), it does not classify in-process.
	for _, pkg := range []string{
		"github.com/lucianoengel/openshield/internal/gateway",
		"github.com/lucianoengel/openshield/cmd/openshield-gateway",
	} {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
		}
		if strings.Contains(string(out), "github.com/lucianoengel/openshield/internal/classify") {
			t.Errorf("%s links internal/classify — the network process must not link the "+
				"parser; body classification runs in the sandboxed worker (D72)", pkg)
		}
	}
}
