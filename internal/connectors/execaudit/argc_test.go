package execaudit_test

import (
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/execaudit"
)

// HIPS-7: a huge attacker-supplied argc must not turn ParseExecve into a CPU denial-of-service
// (each arg scans the whole line). argc is bounded, so parsing returns promptly with a capped arg
// count instead of looping billions of times.
func TestParseExecveBoundsArgc(t *testing.T) {
	line := `type=EXECVE msg=audit(1.0:9): argc=2000000000 a0="x"`
	done := make(chan int, 1)
	go func() {
		e, err := execaudit.ParseExecve(line)
		if err != nil {
			t.Errorf("parse: %v", err)
		}
		done <- len(e.Args)
	}()
	select {
	case n := <-done:
		if n > 1024 {
			t.Errorf("parsed %d args from argc=2e9, want <= the 1024 cap", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ParseExecve did not return promptly on a huge argc — the CPU-DoS bound is missing")
	}
}
