//go:build linux

package watchdog

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// FanotifyResponder is the production Responder: it writes a fanotify_response
// to the fanotify fd. It is deliberately tiny — every decision that separates a
// safe fail-open from a hung host lives in Watchdog, tested without privilege;
// this only marshals the answer the watchdog already decided.
//
// The struct written is `struct fanotify_response { __s32 fd; __u32 response; }`
// — the accessed file's fd followed by FAN_ALLOW or FAN_DENY, exactly as the
// T-005 spike established.
type FanotifyResponder struct {
	NotifyFD int // the fanotify group fd
}

func (r FanotifyResponder) Allow(e PermissionEvent) error { return r.respond(e, unix.FAN_ALLOW) }
func (r FanotifyResponder) Deny(e PermissionEvent) error  { return r.respond(e, unix.FAN_DENY) }

func (r FanotifyResponder) respond(e PermissionEvent, decision uint32) error {
	if e.FD < 0 {
		return fmt.Errorf("watchdog: permission event has no fd to answer")
	}
	var resp [8]byte
	binary.LittleEndian.PutUint32(resp[0:], uint32(e.FD))
	binary.LittleEndian.PutUint32(resp[4:], decision)
	if _, err := unix.Write(r.NotifyFD, resp[:]); err != nil {
		return fmt.Errorf("watchdog: writing fanotify response: %w", err)
	}
	return nil
}

var _ Responder = FanotifyResponder{}
