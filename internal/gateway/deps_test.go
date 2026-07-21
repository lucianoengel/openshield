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
	out, err := exec.Command("go", "list", "-deps",
		"github.com/lucianoengel/openshield/internal/gateway").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "github.com/lucianoengel/openshield/internal/classify") {
		t.Errorf("internal/gateway links internal/classify — the network process must not " +
			"link the parser; body classification runs in the sandboxed worker (D72)")
	}
}
