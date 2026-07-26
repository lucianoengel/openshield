//go:build linux

// Package x11 mediates the X11 CLIPBOARD selection, which is how clipboard control becomes ENFORCEMENT
// rather than observation (DLP-2a increment 2).
//
// Why mediation works on X11 without injecting into applications: the X server holds no clipboard buffer.
// The CLIPBOARD selection has an OWNER (a window), and a paste is a REQUEST to that owner — the requestor
// asks, the owner writes the data onto the requestor's window property and replies. Three consequences,
// and they are the whole design:
//
//   - XFIXES SelectionOwnerNotify tells us the instant someone copies (event-driven, no polling).
//   - The owner's window resolves to the COPYING application (_NET_WM_PID → /proc).
//   - Every SelectionRequest names the REQUESTOR window, which resolves to the PASTING application — so
//     owning the selection lets us decide per destination and refuse a paste outright.
//
// That is the same architecture commercial endpoint DLP implements on Windows by injecting into processes
// to intercept GetClipboardData; X11 simply provides the interposition point natively.
//
// Wayland has no equivalent: its data-control protocols never identify the client receiving a paste, so
// destination-aware policy is impossible there by design (see clipboard.Capabilities).
package x11

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/res"
	"github.com/jezek/xgb/xfixes"
	"github.com/jezek/xgb/xproto"
)

// Decision is what the policy says about one paste request.
type Decision int

const (
	// Allow serves the content to the requesting application.
	Allow Decision = iota
	// Deny refuses the transfer: the requestor is told the conversion failed and receives nothing.
	Deny
)

// Transfer describes one paste request for the decision callback.
type Transfer struct {
	// SourceExe is the application that COPIED, "" if unresolvable (see Copy.SourcePID).
	SourceExe string
	// SourcePID is the copying process, 0 if unresolvable.
	SourcePID int
	// DestExe is the application that is PASTING, "" if unresolvable.
	DestExe string
	// DestPID is the pasting process, 0 if unresolvable.
	DestPID int
	// Bytes is the size of the content being requested.
	Bytes int
}

// Copy describes a captured copy for the capture callback.
type Copy struct {
	// SourceExe is the copying application's executable, "" when it could not be resolved.
	SourceExe string
	// SourcePID is the copying process. It is reported EVEN WHEN SourceExe is empty, because the two fail
	// independently: the X server tells us the pid reliably (X-Resource), but /proc/<pid>/exe is gone the
	// moment that process exits — and a process that copies and immediately exits is both a common helper
	// pattern (xclip forks and the parent exits) and an obvious way to evade attribution by name.
	// A pid with no exe is still evidence; discarding it because the name is missing would be worse.
	SourcePID int
	Content   []byte
}

// Mediator owns the CLIPBOARD selection and answers paste requests under policy.
type Mediator struct {
	// OnCopy is called when a copy is captured; it returns whether the content is SENSITIVE. Only sensitive
	// content is mediated — a non-sensitive copy is left entirely alone, because taking ownership is
	// visible to other clients and doing it for every copy is needless churn.
	OnCopy func(Copy) bool
	// Decide is asked for EVERY paste request of mediated content. It is deliberately per-request: deciding
	// once at copy time would collapse the destination dimension, which is the thing that makes clipboard
	// DLP useful rather than noisy.
	Decide func(Transfer) Decision
	// Excluded reports whether a copy from this source must never be read. Checked BEFORE reading.
	Excluded func(sourceExe string) bool
	// MaxBytes caps a mediated transfer; beyond it the transfer is refused rather than streamed (no INCR).
	MaxBytes int
	// Logf is optional.
	Logf func(format string, a ...any)

	conn  *xgb.Conn
	win   xproto.Window
	root  xproto.Window
	atoms atoms
	// hasXRes reports whether the X-Resource extension is available. It is the RELIABLE way to attribute a
	// window to a process; _NET_WM_PID is only a convention (see pidOfWindow).
	hasXRes bool

	// stopped disables mediation at runtime: no new copy is mediated and ownership is given up. It exists
	// because "turn this off NOW, without restarting the agent" is a real operational need (the fleet
	// emergency-disable shape), and because it is the only honest way to stop mediating — merely
	// relinquishing leaves the mediator running and it re-takes ownership on the very next copy.
	stopped bool

	mu        sync.Mutex
	held      []byte // the mediated content we serve, if we own the selection
	source    string
	sourcePID int
	owning    bool
}

type atoms struct {
	clipboard xproto.Atom
	targets   xproto.Atom
	utf8      xproto.Atom
	str       xproto.Atom
	netWMPID  xproto.Atom
	prop      xproto.Atom // our scratch property for reading a selection
}

// ErrNoXFIXES means the server lacks the extension that reports ownership changes, so event-driven capture
// is unavailable and the caller should fall back to the polled backend.
var ErrNoXFIXES = errors.New("x11: XFIXES unavailable (no selection-ownership notifications)")

// Open connects to the display and prepares an unmapped window to own selections with.
func Open(display string) (*Mediator, error) {
	conn, err := xgb.NewConnDisplay(display)
	if err != nil {
		return nil, fmt.Errorf("x11: connecting to %q: %w", display, err)
	}
	m := &Mediator{conn: conn, MaxBytes: 1 << 20}
	setup := xproto.Setup(conn)
	screen := setup.DefaultScreen(conn)
	m.root = screen.Root

	if err := xfixes.Init(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrNoXFIXES, err)
	}
	// XFIXES requires a version handshake before any other request from the extension.
	if _, err := xfixes.QueryVersion(conn, 5, 0).Reply(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: version handshake: %v", ErrNoXFIXES, err)
	}

	// X-Resource gives a window's owning process at the PROTOCOL level. Without it we fall back to the
	// _NET_WM_PID property, which toolkits set and minimal X clients do not — attribution would then be
	// silently empty for exactly the lightweight helpers an exfiltration path is likely to use.
	if err := res.Init(conn); err == nil {
		if _, verr := res.QueryVersion(conn, 1, 2).Reply(); verr == nil {
			m.hasXRes = true
		}
	}

	wid, err := xproto.NewWindowId(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// A 1x1 InputOnly-ish unmapped window: never visible, exists only to hold selections and receive
	// property/selection events.
	if err := xproto.CreateWindowChecked(conn, screen.RootDepth, wid, screen.Root,
		0, 0, 1, 1, 0, xproto.WindowClassInputOutput, screen.RootVisual,
		xproto.CwEventMask, []uint32{uint32(xproto.EventMaskPropertyChange)}).Check(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("x11: creating the selection window: %w", err)
	}
	m.win = wid

	for _, a := range []struct {
		name string
		dst  *xproto.Atom
	}{
		{"CLIPBOARD", &m.atoms.clipboard}, {"TARGETS", &m.atoms.targets},
		{"UTF8_STRING", &m.atoms.utf8}, {"STRING", &m.atoms.str},
		{"_NET_WM_PID", &m.atoms.netWMPID}, {"OPENSHIELD_CLIP", &m.atoms.prop},
	} {
		rep, err := xproto.InternAtom(conn, false, uint16(len(a.name)), a.name).Reply()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("x11: interning %s: %w", a.name, err)
		}
		*a.dst = rep.Atom
	}

	// Ask to be told whenever the CLIPBOARD owner changes — this is the "a copy happened" signal.
	if err := xfixes.SelectSelectionInputChecked(conn, m.win, m.atoms.clipboard,
		xfixes.SelectionEventMaskSetSelectionOwner).Check(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: selecting ownership input: %v", ErrNoXFIXES, err)
	}
	return m, nil
}

// StopMediating disables mediation and gives up ownership, without disconnecting.
//
// After this the clipboard behaves as if the agent were not there: copies are not captured, ownership is
// not taken, and pastes are served by whoever owns the selection. It is the runtime off-switch, and the
// D17 guarantee that a monitoring component can always be told to get out of the way.
func (m *Mediator) StopMediating() {
	m.mu.Lock()
	m.stopped = true
	m.mu.Unlock()
	m.Relinquish()
}

// Relinquish gives up selection ownership WITHOUT disconnecting.
//
// This is the D17 path that matters. Closing the connection also releases the selection (the X server does
// it for a departing client), so shutdown is safe either way — but a mediator that stops SERVING while
// still connected and still owning the selection leaves every paste on the desktop unanswered. That is the
// clipboard equivalent of the exec gate wedging exec, and it is why stopping mediation is an explicit act
// rather than an implicit consequence of teardown.
func (m *Mediator) Relinquish() {
	m.mu.Lock()
	owning := m.owning
	m.owning, m.held, m.sourcePID = false, nil, 0
	m.mu.Unlock()
	if owning {
		_ = xproto.SetSelectionOwnerChecked(m.conn, xproto.WindowNone, m.atoms.clipboard,
			xproto.TimeCurrentTime).Check()
		m.logf("clipboard/x11: relinquished selection ownership — the clipboard is unmediated and working")
	}
}

// Close relinquishes ownership and disconnects.
//
// Relinquishing is not tidiness, it is the D17 safety property: a mediator that stops while owning the
// selection leaves every paste on the desktop unanswered. A monitoring component must never be able to
// break the user's clipboard.
func (m *Mediator) Close() error {
	m.Relinquish()
	m.conn.Close()
	return nil
}

// Capabilities: X11 mediation gives the full set.
func (m *Mediator) logf(format string, a ...any) {
	if m.Logf != nil {
		m.Logf(format, a...)
	}
}

// Run services the X event loop until ctx is cancelled.
func (m *Mediator) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		// Unblock WaitForEvent by closing the connection; Close() also relinquishes ownership.
		_ = m.Close()
	}()
	for {
		ev, xerr := m.conn.WaitForEvent()
		if ctx.Err() != nil {
			return nil
		}
		if xerr != nil {
			m.logf("clipboard/x11: protocol error: %v", xerr)
			continue
		}
		if ev == nil {
			return nil // connection closed
		}
		switch e := ev.(type) {
		case xfixes.SelectionNotifyEvent:
			m.onOwnerChanged(e)
		case xproto.SelectionRequestEvent:
			m.onSelectionRequest(e)
		case xproto.SelectionClearEvent:
			// Someone else took the selection (another copy, or a clipboard manager). We stop serving —
			// and note it, because a clipboard manager taking ownership is exactly what bypasses
			// per-destination policy, and an operator should see that rather than believe it is enforcing.
			m.mu.Lock()
			m.owning, m.held = false, nil
			m.mu.Unlock()
			m.logf("clipboard/x11: lost selection ownership — later pastes are served by another client " +
				"(a clipboard manager bypasses per-destination policy)")
		}
	}
}

// onOwnerChanged handles "somebody copied".
func (m *Mediator) onOwnerChanged(e xfixes.SelectionNotifyEvent) {
	if e.Owner == m.win || e.Owner == xproto.WindowNone {
		return // our own ownership, or a clear
	}
	m.mu.Lock()
	stopped := m.stopped
	m.mu.Unlock()
	if stopped {
		return // mediation is off: do not capture, do not take ownership
	}
	sourcePID := m.pidOfWindow(e.Owner)
	sourceExe := ""
	if sourcePID > 0 {
		sourceExe = exeOfPID(sourcePID)
	}
	if sourcePID > 0 && sourceExe == "" {
		// The pid resolved but the executable did not: the copier exited between the X query and the
		// /proc read. Worth logging plainly — it is the shape a deliberate evasion takes, and an operator
		// seeing many of these is seeing something worth looking at.
		m.logf("clipboard/x11: copier pid %d exited before it could be named (attribution by pid only)", sourcePID)
	}

	// EXCLUSIONS FIRST — before any read. An excluded application's copy must never enter this process.
	if m.Excluded != nil && m.Excluded(sourceExe) {
		m.logf("clipboard/x11: copy from excluded source %q — not read", sourceExe)
		return
	}
	content, err := m.readSelection()
	if err != nil {
		m.logf("clipboard/x11: reading the selection failed: %v", err)
		return
	}
	if len(content) == 0 {
		return
	}
	sensitive := false
	if m.OnCopy != nil {
		sensitive = m.OnCopy(Copy{SourceExe: sourceExe, SourcePID: sourcePID, Content: content})
	}
	if !sensitive {
		return // leave a non-sensitive copy entirely alone: no ownership churn, no interference
	}
	m.mu.Lock()
	m.held, m.source, m.sourcePID, m.owning = content, sourceExe, sourcePID, true
	m.mu.Unlock()
	// Take ownership so WE answer every subsequent paste request for this content.
	if err := xproto.SetSelectionOwnerChecked(m.conn, m.win, m.atoms.clipboard,
		xproto.TimeCurrentTime).Check(); err != nil {
		m.mu.Lock()
		m.owning, m.held = false, nil
		m.mu.Unlock()
		m.logf("clipboard/x11: could not take ownership (paste is NOT mediated): %v", err)
		return
	}
	m.logf("clipboard/x11: mediating %d sensitive bytes copied by %q (pid %d)", len(content), sourceExe, sourcePID)
}

// onSelectionRequest answers a paste — the enforcement point.
func (m *Mediator) onSelectionRequest(e xproto.SelectionRequestEvent) {
	m.mu.Lock()
	content, source, sourcePID, owning := m.held, m.source, m.sourcePID, m.owning
	m.mu.Unlock()
	if !owning {
		m.refuse(e)
		return
	}
	// TARGETS: tell the requestor which formats we serve. Answering it is not a transfer, so it is not a
	// policy decision — refusing TARGETS would make applications treat the clipboard as empty rather than
	// as denied.
	if e.Target == m.atoms.targets {
		data := make([]byte, 0, 12)
		for _, a := range []xproto.Atom{m.atoms.targets, m.atoms.utf8, m.atoms.str} {
			data = append(data, byte(a), byte(a>>8), byte(a>>16), byte(a>>24))
		}
		if err := xproto.ChangePropertyChecked(m.conn, xproto.PropModeReplace, e.Requestor, e.Property,
			xproto.AtomAtom, 32, uint32(len(data)/4), data).Check(); err != nil {
			m.refuse(e)
			return
		}
		m.notify(e, e.Property)
		return
	}
	if e.Target != m.atoms.utf8 && e.Target != m.atoms.str {
		m.refuse(e) // an unsupported flavor (image, file list): we do not serve it
		return
	}
	if m.MaxBytes > 0 && len(content) > m.MaxBytes {
		// No INCR: refuse rather than stream. Stated in the capability limits.
		m.logf("clipboard/x11: refusing a %d-byte transfer (beyond the cap; INCR is not implemented)", len(content))
		m.refuse(e)
		return
	}

	destPID, destExe := m.pidOfWindow(e.Requestor), ""
	if destPID > 0 {
		destExe = exeOfPID(destPID)
	}
	decision := Allow
	if m.Decide != nil {
		decision = m.Decide(Transfer{SourceExe: source, SourcePID: sourcePID,
			DestExe: destExe, DestPID: destPID, Bytes: len(content)})
	}
	if decision == Deny {
		m.logf("clipboard/x11: DENIED paste of %d bytes to %q (pid %d)", len(content), destExe, destPID)
		m.refuse(e)
		return
	}
	if err := xproto.ChangePropertyChecked(m.conn, xproto.PropModeReplace, e.Requestor, e.Property,
		e.Target, 8, uint32(len(content)), content).Check(); err != nil {
		m.refuse(e)
		return
	}
	m.notify(e, e.Property)
}

// refuse answers with AtomNone, the ICCCM way of saying "conversion failed" — the requestor gets nothing.
func (m *Mediator) refuse(e xproto.SelectionRequestEvent) { m.notify(e, xproto.AtomNone) }

func (m *Mediator) notify(e xproto.SelectionRequestEvent, prop xproto.Atom) {
	ev := xproto.SelectionNotifyEvent{
		Time: e.Time, Requestor: e.Requestor, Selection: e.Selection, Target: e.Target, Property: prop,
	}
	_ = xproto.SendEventChecked(m.conn, false, e.Requestor, 0, string(ev.Bytes())).Check()
}

// readSelection converts the CLIPBOARD into our scratch property and reads it back, capped.
func (m *Mediator) readSelection() ([]byte, error) {
	if err := xproto.ConvertSelectionChecked(m.conn, m.win, m.atoms.clipboard, m.atoms.utf8,
		m.atoms.prop, xproto.TimeCurrentTime).Check(); err != nil {
		return nil, err
	}
	// Wait briefly for the owner's SelectionNotify. A bounded wait, because an unresponsive owner must not
	// stall the mediator.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ev, err := m.conn.PollForEvent()
		if err != nil {
			continue
		}
		if ev == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if sn, ok := ev.(xproto.SelectionNotifyEvent); ok {
			if sn.Property == xproto.AtomNone {
				return nil, nil // the owner declined to convert
			}
			break
		}
		// Other events during the read (including paste requests) are handled inline so we do not deadlock.
		if req, ok := ev.(xproto.SelectionRequestEvent); ok {
			m.onSelectionRequest(req)
		}
	}
	max := m.MaxBytes
	if max <= 0 {
		max = 1 << 20
	}
	rep, err := xproto.GetProperty(m.conn, true, m.win, m.atoms.prop, xproto.GetPropertyTypeAny,
		0, uint32(max/4)+1).Reply()
	if err != nil {
		return nil, err
	}
	if rep == nil {
		return nil, nil
	}
	out := rep.Value
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

// pidOfWindow resolves a window to the process that created it.
//
// X-Resource FIRST, because it is the protocol answering rather than a convention: it reports the pid of
// the client owning the resource, whatever toolkit (or none) that client uses. The _NET_WM_PID fallback
// exists for servers without the extension, but it is set by toolkits and window managers — a minimal X
// client (xclip, a hand-rolled helper, anything an exfiltration path would plausibly use) sets no such
// property, and attribution through it comes back EMPTY. That was not a hypothesis: the first VM run of the
// mediation test attributed a real xclip paste to "" for exactly this reason.
func (m *Mediator) pidOfWindow(w xproto.Window) int {
	if m.hasXRes && w != 0 {
		spec := res.ClientIdSpec{Client: uint32(w), Mask: res.ClientIdMaskLocalClientPID}
		if rep, err := res.QueryClientIds(m.conn, 1, []res.ClientIdSpec{spec}).Reply(); err == nil && rep != nil {
			for _, id := range rep.Ids {
				if id.Spec.Mask&res.ClientIdMaskLocalClientPID != 0 && len(id.Value) > 0 && id.Value[0] > 0 {
					return int(id.Value[0])
				}
			}
		}
	}
	return m.pidFromProperty(w)
}

// pidFromProperty is the _NET_WM_PID fallback, walking up to the toplevel because the requestor is often a
// child window that carries no property of its own.
func (m *Mediator) pidFromProperty(w xproto.Window) int {
	for i := 0; i < 8 && w != 0; i++ {
		rep, err := xproto.GetProperty(m.conn, false, w, m.atoms.netWMPID, xproto.GetPropertyTypeAny,
			0, 1).Reply()
		if err == nil && rep != nil && len(rep.Value) >= 4 {
			return int(uint32(rep.Value[0]) | uint32(rep.Value[1])<<8 |
				uint32(rep.Value[2])<<16 | uint32(rep.Value[3])<<24)
		}
		tree, err := xproto.QueryTree(m.conn, w).Reply()
		if err != nil || tree == nil || tree.Parent == 0 || tree.Parent == w || w == m.root {
			return 0
		}
		w = tree.Parent
	}
	return 0
}

func (m *Mediator) exeOfWindow(w xproto.Window) string {
	if pid := m.pidOfWindow(w); pid > 0 {
		return exeOfPID(pid)
	}
	return ""
}

// exeOfPID resolves a pid to its executable path. An unresolvable pid yields "", which callers must treat
// as "unattributable" rather than inventing a name — a fabricated destination inside an enforcement
// decision is worse than an absent one.
func exeOfPID(pid int) string {
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(exe, " (deleted)")
}
