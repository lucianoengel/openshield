//go:build linux

package dnssink

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// markControl returns a net.Dialer Control that stamps SO_MARK=mark on the upstream socket, so the
// resolver's forwarded query carries the firewall mark that the transparent redirect exempts (the
// loop-break). Setting SO_MARK needs CAP_NET_ADMIN, so this is exercised only under the gated VM test.
func markControl(mark int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return setErr
	}
}
