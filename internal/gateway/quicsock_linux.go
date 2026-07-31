//go:build linux

package gateway

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenQUICRedirect opens the transparent UDP socket the TPROXY rule diverts UDP/443 into.
//
// Two options, both load-bearing. IP_TRANSPARENT is what lets the socket receive packets whose destination
// is not a local address — every diverted flow, by definition. IP_RECVORIGDSTADDR is what attaches that
// destination to each datagram, and it is the one fact an egress decision is made on: without it the plane
// knows a packet arrived and not where it was going.
func ListenQUICRedirect(addr string) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					sockErr = err
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					sockErr = fmt.Errorf("IP_TRANSPARENT: %w", err)
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
					sockErr = fmt.Errorf("IP_RECVORIGDSTADDR: %w", err)
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("gateway: expected a *net.UDPConn, got %T", pc)
	}
	return uc, nil
}

// originalDst recovers the destination the client was actually addressing.
//
// An error is NOT "no destination" — it is "this socket is not receiving the cmsg", a misconfiguration
// rather than traffic, and the caller says so rather than guessing. A guessed destination is a decision
// made about a different flow, and the plane would look perfectly healthy while making it.
func originalDst(oob []byte) (*net.UDPAddr, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parsing control messages: %w", err)
	}
	for i := range msgs {
		sa, err := unix.ParseOrigDstAddr(&msgs[i])
		if err != nil {
			continue
		}
		switch v := sa.(type) {
		case *unix.SockaddrInet4:
			return &net.UDPAddr{IP: net.IP(v.Addr[:]), Port: v.Port}, nil
		case *unix.SockaddrInet6:
			return &net.UDPAddr{IP: net.IP(v.Addr[:]), Port: v.Port}, nil
		}
	}
	return nil, fmt.Errorf("no IP_ORIGDSTADDR control message on the datagram")
}

// transparentControl makes a socket bindable to an address this host does not own.
//
// The plane forwards each flow FROM THE CLIENT'S OWN ADDRESS, so the destination sees the client rather
// than the gateway. That is what makes the return path work without any relay code at all: the reply is
// addressed to the client, it is an ordinary forwarded packet through this gateway, and it is not UDP/443
// so the divert rule does not catch it. The kernel delivers it. A gateway that answered from its own
// address would have to forge the source on the way back, and a QUIC client discards packets from an
// unexpected server address — which fails in a way indistinguishable from the network being broken.
func transparentControl(_, _ string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockErr = err
			return
		}
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	}); err != nil {
		return err
	}
	return sockErr
}
