package execmon

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// makeMeta builds a synthetic 24-byte fanotify_event_metadata record.
func makeMeta(eventLen uint32, mask uint64, fd, pid int32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], eventLen)
	b[4] = 3 // vers
	binary.LittleEndian.PutUint16(b[6:], 24)
	binary.LittleEndian.PutUint64(b[8:], mask)
	binary.LittleEndian.PutUint32(b[16:], uint32(fd))
	binary.LittleEndian.PutUint32(b[20:], uint32(pid))
	return b
}

func TestDecodeMeta(t *testing.T) {
	rec := makeMeta(24, 0x40000, 7, 4242)
	m, rest, ok := decodeMeta(rec)
	if !ok {
		t.Fatal("a well-formed record failed to decode")
	}
	if m.FD != 7 || m.PID != 4242 || m.Mask != 0x40000 || m.EventLen != 24 {
		t.Fatalf("decoded %+v, want fd=7 pid=4242 mask=0x40000 len=24", m)
	}
	if len(rest) != 0 {
		t.Fatalf("rest = %d bytes, want 0", len(rest))
	}
}

func TestDecodeMetaTwoRecords(t *testing.T) {
	buf := append(makeMeta(24, 1, 3, 100), makeMeta(24, 2, 4, 200)...)
	m1, rest, ok := decodeMeta(buf)
	if !ok || m1.PID != 100 || m1.FD != 3 {
		t.Fatalf("first record decoded %+v ok=%v", m1, ok)
	}
	m2, rest2, ok := decodeMeta(rest)
	if !ok || m2.PID != 200 || m2.FD != 4 {
		t.Fatalf("second record decoded %+v ok=%v", m2, ok)
	}
	if len(rest2) != 0 {
		t.Fatalf("trailing bytes = %d, want 0", len(rest2))
	}
}

func TestDecodeMetaTruncated(t *testing.T) {
	// A 10-byte buffer is shorter than the fixed struct → not ok, no panic.
	if _, _, ok := decodeMeta(make([]byte, 10)); ok {
		t.Fatal("a truncated buffer decoded as ok — a short read must not be accepted")
	}
	// A record claiming a length past the buffer is malformed.
	rec := makeMeta(1000, 1, 3, 100) // event_len 1000 but only 24 bytes present
	if _, _, ok := decodeMeta(rec); ok {
		t.Fatal("a record whose event_len overruns the buffer decoded as ok")
	}
}

func TestDenyEvaluatorBlocks(t *testing.T) {
	ev := DenyEvaluator{
		DenyPaths:     map[string]bool{"/opt/evil/backdoor": true},
		DenyBasenames: map[string]bool{"nc": true},
	}
	ctx := context.Background()
	cases := []struct {
		path string
		want watchdog.Verdict
	}{
		{"/opt/evil/backdoor", watchdog.VerdictBlock}, // absolute-path deny
		{"/usr/bin/nc", watchdog.VerdictBlock},        // basename deny
		{"/tmp/x/nc", watchdog.VerdictBlock},          // basename deny regardless of dir
		{"/usr/bin/ls", watchdog.VerdictAllow},        // benign
		{"", watchdog.VerdictAllow},                   // unresolved path → allow (positive control)
	}
	for _, c := range cases {
		v, err := ev.Evaluate(ctx, watchdog.PermissionEvent{Path: c.path})
		if err != nil {
			t.Fatalf("%q: unexpected error %v", c.path, err)
		}
		if v != c.want {
			t.Errorf("Evaluate(%q) = %v, want %v", c.path, v, c.want)
		}
	}
}

func TestDenyEvaluatorBehaviorFloor(t *testing.T) {
	// A benign path with the floor set does not block; the floor only blocks a
	// behaviorally-suspicious exec (the behavioral analyzer scores on path/args). With no
	// args here, a plain benign path stays below any positive floor.
	ev := DenyEvaluator{BehaviorFloor: 0.5}
	v, _ := ev.Evaluate(context.Background(), watchdog.PermissionEvent{Path: "/usr/bin/ls"})
	if v != watchdog.VerdictAllow {
		t.Fatalf("a benign exec blocked under a behavioral floor: %v", v)
	}
}

func TestLoadDenyList(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(f, []byte("# comment\n/opt/evil/x\n\nnc\nncat\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths, bases, err := LoadDenyList(f)
	if err != nil {
		t.Fatal(err)
	}
	if !paths["/opt/evil/x"] || !bases["nc"] || !bases["ncat"] || paths["nc"] {
		t.Fatalf("parsed deny-list wrong: paths=%v bases=%v", paths, bases)
	}
	if _, _, err := LoadDenyList(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing deny-list file must error (never silently disarm)")
	}
}
