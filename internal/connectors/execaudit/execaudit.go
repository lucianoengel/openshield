// Package execaudit is the process-exec producer (Phase E / HIPS, E1). It parses Linux
// auditd EXECVE + SYSCALL record pairs into ProcessSubject Events, so process executions
// enter the SAME pipeline as file, network, and log events — feeding the behavioral
// detector (D110) and the process enforcers (D111).
//
// It is a pure parser: the auditd record text (untrusted, from the audit subsystem) is
// handled here and tested in ordinary Go, separate from the log-tail / audit-socket I/O.
// A record pair is EXECVE (the argument vector) plus the SYSCALL that carries pid/ppid/exe,
// linked by their shared audit event id. Reading the audit log is privileged (a deployment
// concern); the observe variant here needs no fanotify permission mode (external-gated, B2).
//
// Auditd emits exec METADATA (D10/D29) — argv, pid, exe path — never process memory.
package execaudit

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Syscall is the parsed content of an audit SYSCALL record for an exec.
type Syscall struct {
	AuditID string // the "timestamp:serial" that links the record pair
	PID     int32
	PPID    int32
	Exe     string
}

// ParseSyscall parses a "type=SYSCALL ..." exec record. It reads pid, ppid, and exe, and the
// audit event id from "msg=audit(TS:SERIAL):". A record missing the id or the exe is an
// error — an exec event with no executable or no correlation id is not usable (D17).
func ParseSyscall(line string) (Syscall, error) {
	id, err := auditID(line)
	if err != nil {
		return Syscall{}, err
	}
	s := Syscall{AuditID: id}
	s.Exe = unquote(field(line, "exe"))
	if s.Exe == "" {
		return Syscall{}, fmt.Errorf("execaudit: SYSCALL record has no exe")
	}
	if v := field(line, "pid"); v != "" {
		n, _ := strconv.Atoi(v)
		s.PID = int32(n)
	}
	if v := field(line, "ppid"); v != "" {
		n, _ := strconv.Atoi(v)
		s.PPID = int32(n)
	}
	return s, nil
}

// Execve is the parsed argument vector from a "type=EXECVE ..." record.
type Execve struct {
	AuditID string
	Args    []string
}

// ParseExecve parses a "type=EXECVE ..." record: argc=N followed by a0.."a(N-1)". The args
// are read in order and unquoted. A record missing the audit id is an error.
func ParseExecve(line string) (Execve, error) {
	id, err := auditID(line)
	if err != nil {
		return Execve{}, err
	}
	e := Execve{AuditID: id}
	argc := 0
	if v := field(line, "argc"); v != "" {
		argc, _ = strconv.Atoi(v)
	}
	for i := 0; i < argc; i++ {
		a := field(line, "a"+strconv.Itoa(i))
		e.Args = append(e.Args, unquote(a))
	}
	return e, nil
}

// ToEvent combines a matched SYSCALL + EXECVE pair into a ProcessSubject Event. The two MUST
// share an audit id (they describe the SAME exec) — mismatched records are an error, because
// stitching an argv onto the wrong process would misattribute the execution. parent_path is
// not in the audit pair (it needs a second lookup); it is left empty here and enriched by a
// process-tree resolver as a follow-up.
func ToEvent(s Syscall, e Execve) (*corev1.Event, error) {
	if s.AuditID == "" || s.AuditID != e.AuditID {
		return nil, fmt.Errorf("execaudit: SYSCALL id %q and EXECVE id %q do not match", s.AuditID, e.AuditID)
	}
	return &corev1.Event{
		ConnectorId: "execaudit",
		EventId:     "exec-" + s.AuditID,
		Kind:        corev1.EventKind_EVENT_KIND_PROCESS_EXEC,
		Target: &corev1.Event_Process{Process: &corev1.ProcessSubject{
			Pid:      s.PID,
			Ppid:     s.PPID,
			ExecPath: s.Exe,
			Args:     e.Args,
		}},
	}, nil
}

// auditID extracts the "TS:SERIAL" from "msg=audit(1626351234.123:456):".
func auditID(line string) (string, error) {
	i := strings.Index(line, "audit(")
	if i < 0 {
		return "", fmt.Errorf("execaudit: no audit() id in record")
	}
	rest := line[i+len("audit("):]
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		return "", fmt.Errorf("execaudit: malformed audit() id")
	}
	id := rest[:end]
	if !strings.Contains(id, ":") {
		return "", fmt.Errorf("execaudit: audit id %q missing serial", id)
	}
	return id, nil
}

// field returns the value of "key=..." from an audit record, up to the next space. It
// requires a whole-token key (preceded by start-of-string or a space) so "pid" does not
// match "ppid".
func field(line, key string) string {
	needle := key + "="
	from := 0
	for {
		i := strings.Index(line[from:], needle)
		if i < 0 {
			return ""
		}
		pos := from + i
		if pos == 0 || line[pos-1] == ' ' {
			v := line[pos+len(needle):]
			if sp := strings.IndexByte(v, ' '); sp >= 0 {
				return v[:sp]
			}
			return v
		}
		from = pos + len(needle)
	}
}

// unquote strips surrounding double quotes from an audit value (argv items and exe are
// quoted). A hex-encoded value (auditd uses hex for args with special chars) is left as-is —
// decoding it is a follow-up; the detector sees the hex, which is still a distinct token.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
