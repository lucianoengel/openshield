//go:build !linux

package gateway

import (
	"net"
	"syscall"
)

func ListenQUICRedirect(string) (*net.UDPConn, error) { return nil, errQUICUnsupported }

func originalDst([]byte) (*net.UDPAddr, error) { return nil, errQUICUnsupported }

func transparentControl(_, _ string, _ syscall.RawConn) error { return errQUICUnsupported }
