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
	if m.EventLen < metaLen || int(m.EventLen) > len(buf) {
		return m, nil, false // a length that under/over-runs the buffer is malformed
	}
	return m, buf[m.EventLen:], true
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
}

// Evaluate returns VerdictBlock on a deny-list hit or an above-floor behavioral score,
// else VerdictAllow. It never returns an error.
func (d DenyEvaluator) Evaluate(_ context.Context, e watchdog.PermissionEvent) (watchdog.Verdict, error) {
	path := e.Path
	if path != "" {
		if d.DenyPaths[path] {
			return watchdog.VerdictBlock, nil
		}
		if d.DenyBasenames[filepath.Base(path)] {
			return watchdog.VerdictBlock, nil
		}
		if d.BehaviorFloor > 0 {
			if f := behavioral.Analyze(path, "", nil); f.Score >= d.BehaviorFloor {
				return watchdog.VerdictBlock, nil
			}
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
