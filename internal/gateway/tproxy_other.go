//go:build !linux

package gateway

import (
	"fmt"
	"net"
)

// ListenTransparent is Linux-only (IP_TRANSPARENT/TPROXY). The stub lets the tree
// cross-compile (D9); the inline data-plane ships on Linux.
func ListenTransparent(addr string) (net.Listener, error) {
	return nil, fmt.Errorf("gateway: transparent TPROXY listening is Linux-only")
}
