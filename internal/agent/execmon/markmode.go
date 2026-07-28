package execmon

// MarkMode is the breadth of the kernel mark, chosen from the gate's SEMANTICS rather than from a
// preference for narrowness (D331).
//
// The two fail in opposite directions: a mount mark can only WASTE — an event, and a blocked process,
// for every execution on the mount, including ones the gate does not police — while per-file marks can
// only MISS, because anything unmarked produces no event at all and, under default-deny, therefore RUNS.
// In a security control those are not symmetric risks, so the narrow mode is used only where the scope
// is already defined and defended.
type MarkMode int

const (
	// MarkMount marks the whole mount each watched path lives on. Always correct, and the right choice
	// for any GLOBAL signal: a deny-list names binaries to refuse wherever they run from, and a
	// behavioural floor or a pipeline verdict decides on whatever it is shown.
	MarkMount MarkMode = iota
	// MarkPerFile marks each executable under the watched paths individually. Correct only for a SCOPED
	// signal — application whitelisting, whose reach D330 bounded to the monitored directories — and it
	// requires that files appearing later are marked as they appear, or the narrowing becomes a bypass.
	MarkPerFile
)

func (m MarkMode) String() string {
	if m == MarkPerFile {
		return "per-file"
	}
	return "mount"
}
