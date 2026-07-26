package printguard

import (
	"fmt"
	"net"
	"time"
)

// DefaultTimeout bounds one verdict round trip. Printing is interactive: a user who pressed Print expects
// paper, so the budget is generous relative to the exec gate but still bounded.
const DefaultTimeout = 10 * time.Second

// Ask submits a job for a verdict.
//
// EVERY failure returns an error, and the caller (the filter) turns an error into ALLOW — see the filter's
// fail-open discipline. A verdict is never guessed from a broken exchange: a mismatched response id, a
// short frame, or an unknown verdict byte is an error, not a decision.
func Ask(socket string, req Request, timeout time.Duration) (Verdict, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("unix", socket, time.Until(deadline))
	if err != nil {
		return VerdictAllow, fmt.Errorf("printguard: dial %s: %w", socket, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return VerdictAllow, err
	}
	if err := WriteRequest(conn, req); err != nil {
		return VerdictAllow, fmt.Errorf("printguard: write: %w", err)
	}
	resp, err := ReadResponse(conn)
	if err != nil {
		return VerdictAllow, fmt.Errorf("printguard: read: %w", err)
	}
	if resp.ID != req.ID {
		// Answering job A with job B's verdict would be silently wrong in both directions — the same
		// reasoning as the exec gate's cross-talk guard.
		return VerdictAllow, fmt.Errorf("%w: got %d, want %d", ErrIDMismatch, resp.ID, req.ID)
	}
	return resp.Verdict, nil
}
