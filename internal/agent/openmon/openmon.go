// Package openmon is the privileged FAN_OPEN_PERM producer (B2): it marks watched DIRECTORIES,
// reads each file-open permission event, and hands it to the watchdog, which answers the kernel
// under a hard budget (D18).
//
// It is execmon's twin for opens rather than executions, and differs in two ways that matter.
//
// THE MARK IS AN INODE MARK, NEVER A MOUNT. execmon marks the mount because a directory mark does not
// deliver FAN_OPEN_EXEC_PERM for files executed within it (D224, measured). Opens are different: a
// directory mark with FAN_EVENT_ON_CHILD delivers opens of files in that directory. That difference is
// worth having, because marking a mount for OPENS would route every open on the host — the package
// manager's, the shell's, the engine's own — through a permission window that blocks the caller
// uninterruptibly. Even fail-open, that is a tax on every syscall and any bug in the path is a
// system-wide hang.
//
// A MOUNT-WIDE SCOPE IS THEREFORE REFUSED, not merely discouraged.
//
// NOTHING HERE READS FILE CONTENT. The event carries the kernel's descriptor and the evaluator decides
// what to do with it; this package moves events, and the split keeps the read where its bound and its
// budget are (see internal/agent/openipc).
package openmon

import "errors"

// ErrMountScope is returned when a caller asks for a mount-wide mark.
//
// It is an error rather than a warning because the consequence is not a noisy log: every open on the
// host would enter a permission window, and a gate whose blast radius is the whole machine is not a
// configuration this should let an operator reach by accident.
var ErrMountScope = errors.New("openmon: a mount-wide scope is refused — every open on the host would " +
	"enter a permission window; name directories instead")

// ErrNoPaths is returned when no directory was given. A producer with nothing marked would run, report
// itself active, and deliver no events — the inert-control failure this project keeps finding.
var ErrNoPaths = errors.New("openmon: no directories to watch")

// DefaultMaxInFlight bounds concurrently answered permission events.
//
// It matches the IPC client's default: the two are the same queue seen from either end, and a producer
// allowed to run ahead of the client's connection pool would only move the waiting from one side of the
// socket to the other.
const DefaultMaxInFlight = 8
