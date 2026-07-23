//go:build !linux

package dnssink

import "syscall"

// markControl is inert off linux: SO_MARK and the transparent redirect that needs it are linux-only, and
// the resolver's Mark is never set to a non-zero value on other platforms. Returning nil leaves the Dialer
// with no Control hook, so a (non-linux) Mark > 0 simply dials plainly rather than failing to build.
func markControl(mark int) func(network, address string, c syscall.RawConn) error {
	return nil
}
