// Package execmon is the privileged fanotify exec-permission PRODUCER (HIPS-3): it
// marks FAN_OPEN_EXEC_PERM on watched paths, reads each exec-permission event, and
// drives the fail-open watchdog to answer the kernel ALLOW/DENY before the executing
// process (parked uninterruptibly) proceeds — the piece that turns the built-and-tested
// exec-deny DECISION (D217) into real inline prevention on a live kernel.
//
// It holds NO content parser: it runs with elevated privilege, and a parser memory bug
// there is host compromise (the reason the privileged binary is dependency-checked). The
// decision it drives is the pure, parser-free DenyEvaluator below — an operator exec
// deny-list plus an optional behavioral-suspicion threshold, both json-free — so the
// whole privileged path stays parser-free. (Driving the full OPA-pipeline DENY_EXEC
// inline needs an IPC decider to the unprivileged engine; that is a later increment.)
package execmon

import (
	"bufio"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	"github.com/lucianoengel/openshield/internal/behavioral"
)

// metaLen is the fixed size of struct fanotify_event_metadata in FAN_CLASS_CONTENT mode.
const metaLen = 24

// meta is one decoded fanotify_event_metadata record.
type meta struct {
	EventLen uint32
	Vers     uint8
	Mask     uint64
	FD       int32
	PID      int32
}

// decodeMeta decodes the first fanotify_event_metadata from buf and returns the
// remaining bytes. ok is false for a short buffer or a length that runs past the
// buffer — a malformed read must never panic or over-read; the caller fails open.
//
// struct fanotify_event_metadata { __u32 event_len; __u8 vers; __u8 reserved;
// __u16 metadata_len; __aligned_u64 mask; __s32 fd; __s32 pid; }
func decodeMeta(buf []byte) (m meta, rest []byte, ok bool) {
	if len(buf) < metaLen {
		return meta{}, buf, false
	}
	m.EventLen = binary.LittleEndian.Uint32(buf[0:4])
	m.Vers = buf[4]
	// buf[5] reserved; buf[6:8] metadata_len
	m.Mask = binary.LittleEndian.Uint64(buf[8:16])
	m.FD = int32(binary.LittleEndian.Uint32(buf[16:20]))
	m.PID = int32(binary.LittleEndian.Uint32(buf[20:24]))
	// COMPARED IN uint64, NOT int, AND THIS IS A FIX. `int(m.EventLen) > len(buf)` was the original, and
	// on a 32-bit platform `int` is 32 bits, so an event_len of 0xFFFFFFFF converts to -1: the
	// over-run check reads `-1 > 24` and passes, the under-run check reads `0xFFFFFFFF < 24` on the
	// UNSIGNED field and also passes, and the slice below panics with `[4294967295:24]`. The agent
	// builds for linux/386 and linux/arm today. Found by FuzzDecodeMeta under GOARCH=386; on amd64 the
	// same input is rejected correctly, which is why nothing had noticed.
	//
	// The order of the conversion is what decides this. `connectors/fanotify.ParseEvent` converts to int
	// BEFORE comparing, so its negative value trips the under-run check and it is accidentally safe —
	// same class, opposite outcome, and neither site says which discipline it is relying on.
	if m.EventLen < metaLen || uint64(m.EventLen) > uint64(len(buf)) {
		return m, nil, false // a length that under/over-runs the buffer is malformed
	}
	// Safe as an int now: the guard above proved EventLen fits within len(buf).
	return m, buf[int(m.EventLen):], true
}

// DenyEvaluator is the pure, parser-free inline exec decider (satisfies watchdog.Evaluator).
// It blocks an execution whose binary path is on an operator deny-list (by absolute path or
// basename) or whose exec metadata is behaviorally suspicious above a threshold, and allows
// everything else. It never errors — a pure decision that fits the permission budget with no
// content parsing and no IPC. Because it holds no corev1/OPA, it is the decider the
// privileged (parser-free) binary can carry.
type DenyEvaluator struct {
	DenyPaths     map[string]bool // absolute exec paths to block
	DenyBasenames map[string]bool // exec basenames to block (e.g. "nc", "ncat")
	BehaviorFloor float64         // block when behavioral.Score >= this; 0 disables the behavioral gate

	// Application whitelisting (default-deny): when either allow map is non-empty, a RESOLVED exec
	// whose path/basename is NOT allowlisted is blocked. The deny-list and behavioral gate above still
	// apply first (deny wins over allow), and an unresolved path is allowed (we cannot verify it —
	// availability over a false block, D17).
	AllowPaths     map[string]bool
	AllowBasenames map[string]bool
	// AllowScope BOUNDS the default-deny to the directories the operator asked to police, and it is
	// load-bearing rather than tidy (D330).
	//
	// The kernel mark is necessarily BROADER than the configuration: exec-permission events are only
	// delivered for a MOUNT mark, because a directory inode mark does not deliver FAN_OPEN_EXEC_PERM for
	// files executed inside it. So the agent observes every execution on the mount. A deny-list is
	// unaffected — it refuses exactly what it names — but an unbounded default-deny refuses every
	// executable on the filesystem, which was measured on a live kernel to refuse `sudo`, `cat` and
	// `/bin/bash`, taking sshd's login shell with it. The machine could then only be recovered by a
	// power cycle: stopping the agent needs exec, and logging in needs exec.
	//
	// EMPTY MEANS UNSCOPED, and the caller must not leave it so when an allowlist is set. That is
	// enforced at the wiring site rather than here, because this type has no way to tell "the operator
	// declared no directories" from "nobody passed them through".
	AllowScope []string
}

// inScope reports whether a resolved exec path lies under a monitored directory — the boundary the
// default-deny is allowed to act inside.
func (d DenyEvaluator) inScope(path string) bool {
	for _, dir := range d.AllowScope {
		if dir == "" {
			continue
		}
		if path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/") {
			return true
		}
	}
	return false
}

func (d DenyEvaluator) allowlistActive() bool {
	return len(d.AllowPaths) > 0 || len(d.AllowBasenames) > 0
}

// Evaluate returns VerdictBlock on a deny-list hit, an above-floor behavioral score, or (in
// allowlist mode) a resolved exec that is not allowlisted; else VerdictAllow. It never errors.
func (d DenyEvaluator) Evaluate(_ context.Context, e watchdog.PermissionEvent) (watchdog.Verdict, error) {
	path := e.Path
	if path != "" {
		base := filepath.Base(path)
		// Deny and behavioral FIRST — these can block even an allowlisted binary (deny > allow).
		if d.DenyPaths[path] || d.DenyBasenames[base] {
			return watchdog.VerdictBlock, nil
		}
		if d.BehaviorFloor > 0 {
			if f := behavioral.Analyze(path, "", nil); f.Score >= d.BehaviorFloor {
				return watchdog.VerdictBlock, nil
			}
		}
		// Application whitelisting: default-deny a resolved exec that is not on the allowlist — but ONLY
		// inside the monitored directories. An exec elsewhere on the mount was never in the scope the
		// operator declared, and refusing it is what makes the host unrecoverable (see AllowScope).
		if d.allowlistActive() && d.inScope(path) && !d.AllowPaths[path] && !d.AllowBasenames[base] {
			return watchdog.VerdictBlock, nil
		}
	}
	return watchdog.VerdictAllow, nil
}

var _ watchdog.Evaluator = DenyEvaluator{}

// LoadDenyList reads a deny-list file — one exec path or basename per non-empty,
// non-#-comment line. An absolute path (leading '/') denies that exact binary; any
// other token denies by basename. A missing file is an error (a mis-typed deny-list
// path must not silently disarm the control).
func LoadDenyList(path string) (paths, basenames map[string]bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	paths, basenames = map[string]bool{}, map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "/") {
			paths[t] = true
		} else {
			basenames[t] = true
		}
	}
	return paths, basenames, sc.Err()
}
