//go:build linux

package gateway

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenTransparent creates a TCP listener with IP_TRANSPARENT set, so a TPROXY
// nftables/iptables rule can redirect flows to it and each accepted connection's LocalAddr
// is the ORIGINAL destination the client meant to reach (TPROXY preserves it, so no
// getsockopt(SO_ORIGINAL_DST) is needed). Needs CAP_NET_ADMIN — a caller that cannot create
// it must fail to WIRE (log + continue), never fail the network closed.
func ListenTransparent(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					sockErr = err
					return
				}
				// IP_TRANSPARENT lets the socket accept connections whose local address is not
				// a local IP (the redirected original destination).
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}
