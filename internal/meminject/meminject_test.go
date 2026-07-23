package meminject

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleMaps = `55e000-55e001 r-xp 00000000 08:01 100 /usr/bin/app
55e100-55e101 rw-p 00001000 08:01 100 /usr/bin/app
7f0000-7f0001 rwxp 00000000 00:00 0
7f1000-7f1001 r--p 00000000 08:01 200 /lib/libc.so
7f2000-7f2001 rwxs 00000000 00:00 0
malformed line here
zz-zz r-xp 0 0 0 /bad/addr
`

func TestParseMapsAndWX(t *testing.T) {
	regions := parseMaps(strings.NewReader(sampleMaps))
	// The two valid-address W+X lines are 7f0000 (rwxp) and 7f2000 (rwxs); malformed/bad-addr are skipped.
	suspects := SuspectRegions(regions)
	if len(suspects) != 2 {
		t.Fatalf("SuspectRegions = %d, want 2 (the rwxp + rwxs); got %+v", len(suspects), suspects)
	}
	for _, s := range suspects {
		if !isWX(s.Perms) {
			t.Errorf("flagged a non-W+X region: %q", s.Perms)
		}
	}
	// A normal code (r-xp) and data (rw-p) region must NOT be flagged.
	if isWX("r-xp") || isWX("rw-p") || isWX("r--p") {
		t.Error("a code/data region was treated as W+X")
	}
	if !isWX("rwxp") {
		t.Error("rwxp is not W+X?")
	}
}

func TestScanAllSkipsUnreadable(t *testing.T) {
	root := t.TempDir()
	// A readable pid with a W+X region.
	mk := func(pid, content string) string {
		d := filepath.Join(root, pid)
		os.MkdirAll(d, 0o755)
		return d
	}
	d1 := mk("100", "")
	os.WriteFile(filepath.Join(d1, "maps"), []byte("7f0000-7f0001 rwxp 0 00:00 0 \n"), 0o644)
	// A pid dir with NO maps file → unreadable.
	mk("200", "")
	// A non-pid dir → ignored.
	os.MkdirAll(filepath.Join(root, "notapid"), 0o755)

	suspects, unreadable := ScanAll(root)
	if len(suspects) != 1 || len(suspects[100]) != 1 {
		t.Fatalf("suspects = %+v, want pid 100 with 1 region", suspects)
	}
	if unreadable != 1 {
		t.Errorf("unreadable = %d, want 1 (pid 200's missing maps)", unreadable)
	}
}
