package execaudit

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync/atomic"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The exec producer source (HIPS-5c). auditd emits an exec as a SYSCALL record immediately
// followed by an EXECVE record sharing one audit id; the pure parsers (ParseSyscall/ParseExecve/
// ToEvent) are built, but nothing read a live stream and PAIRED the records into Events. Scan does
// that: it reads auditd records from r (a tailed audit log or the audit stream), pairs each
// SYSCALL with its EXECVE by audit id, and delivers the combined ProcessSubject Event to sink —
// turning the parser into a running connector that feeds the pipeline (like the DNS source).
//
// A malformed record is DROPPED and COUNTED, never fatal (D17/D28). The pending-pair buffer is
// BOUNDED: a flood of unpaired records (a half of every pair missing) cannot grow memory without
// limit — the oldest pending record is evicted past the cap.

const maxPending = 4096

// maxAuditLine bounds a single record; auditd lines are large (a long argv) but not unbounded.
const maxAuditLine = 1 << 20 // 1 MiB

type partial struct {
	syscall *Syscall
	execve  *Execve
}

// Scanner pairs auditd SYSCALL+EXECVE records from a stream into Events.
type Scanner struct {
	sink    func(*corev1.Event)
	dropped atomic.Int64
	// startTicks captures the process start-time at observation (HIPS-7), so an enforcement can
	// revalidate the identity and spare a recycled pid. Injectable; defaults to the real /proc reader
	// (0 when the process already exited — best-effort, honestly no revalidation for that event).
	startTicks func(pid int32) uint64
}

// NewScanner builds a scanner delivering paired exec Events to sink.
func NewScanner(sink func(*corev1.Event)) *Scanner {
	return &Scanner{sink: sink, startTicks: readStartTicks}
}

// Dropped reports how many records were dropped (malformed, or evicted unpaired).
func (s *Scanner) Dropped() int64 { return s.dropped.Load() }

// Scan reads records from r until it is exhausted or ctx is cancelled, pairing and emitting.
func (s *Scanner) Scan(ctx context.Context, r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxAuditLine)

	pending := map[string]*partial{}
	var order []string // FIFO of pending ids, to evict the oldest when over the cap

	get := func(id string) *partial {
		p := pending[id]
		if p == nil {
			p = &partial{}
			pending[id] = p
			order = append(order, id)
		}
		return p
	}
	emitIfComplete := func(id string) {
		p := pending[id]
		if p == nil || p.syscall == nil || p.execve == nil {
			return
		}
		if ev, err := ToEvent(*p.syscall, *p.execve); err == nil {
			// Capture the process start-time NOW (HIPS-7): with the pid it identifies this exact
			// process instance, so a later KILL can spare a recycled pid.
			if ps := ev.GetProcess(); ps != nil && s.startTicks != nil {
				ps.StartTicks = s.startTicks(ps.GetPid())
			}
			s.sink(ev)
		} else {
			s.dropped.Add(1)
		}
		delete(pending, id)
	}
	evict := func() {
		for len(pending) > maxPending && len(order) > 0 {
			old := order[0]
			order = order[1:]
			if _, ok := pending[old]; ok {
				delete(pending, old) // an unpaired record aged out — count it as dropped
				s.dropped.Add(1)
			}
		}
	}

	// handleLine parses one record and pairs it, RECOVERING from any panic (ENG-2): the engine
	// parses attacker-influenced audit text in-process, so a panic on a crafted record must be
	// contained (dropped + counted), never crash the engine.
	handleLine := func(line string) {
		defer func() {
			if r := recover(); r != nil {
				s.dropped.Add(1)
			}
		}()
		switch {
		case strings.Contains(line, "type=SYSCALL"):
			rec, err := ParseSyscall(line)
			if err != nil {
				s.dropped.Add(1)
				return
			}
			get(rec.AuditID).syscall = &rec
			emitIfComplete(rec.AuditID)
		case strings.Contains(line, "type=EXECVE"):
			rec, err := ParseExecve(line)
			if err != nil {
				s.dropped.Add(1)
				return
			}
			get(rec.AuditID).execve = &rec
			emitIfComplete(rec.AuditID)
		}
	}

	for sc.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		handleLine(sc.Text())
		evict()
	}
	return sc.Err()
}
