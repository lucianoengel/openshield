//go:build linux

// Command t005-fanotify establishes what a fanotify listener actually receives,
// so the event schema (T-003) can stop guessing.
//
// # The question
//
// The Event contract currently models a filesystem subject as a oneof over
// "resolved path" or "opaque kernel handle", because nobody had checked which
// one arrives. That oneof is the weakest point in the T-003 design. This spike
// settles it.
//
// Secondary question, flagged unverified in review: is golang.org/x/sys/unix
// sufficient for fanotify work, or does the agent need CGO?
//
// # Scope discipline
//
// The dev sandbox cannot obtain real CAP_SYS_ADMIN (measured: rootless Podman's
// userns capability is not the same capability). So this spike can exercise the
// UNPRIVILEGED modes directly and must reason about the privileged mode from
// what the unprivileged results reveal plus the kernel's documented behaviour.
//
// That limitation belongs to the dev loop, not the product. The shipped agent
// runs as root with CAP_SYS_ADMIN. Nothing here may narrow the product's design
// to fit this sandbox.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// struct fanotify_event_metadata — 24 bytes, stable since v3 of the ABI.
type eventMetadata struct {
	EventLen    uint32
	Vers        uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	Fd          int32
	Pid         int32
}

const metadataLen = 24

// struct fanotify_event_info_header — precedes every info record.
type infoHeader struct {
	InfoType uint8
	Pad      uint8
	Len      uint16
}

func infoTypeName(t uint8) string {
	switch t {
	case unix.FAN_EVENT_INFO_TYPE_FID:
		return "FID"
	case unix.FAN_EVENT_INFO_TYPE_DFID:
		return "DFID"
	case unix.FAN_EVENT_INFO_TYPE_DFID_NAME:
		return "DFID_NAME"
	case unix.FAN_EVENT_INFO_TYPE_PIDFD:
		return "PIDFD"
	case unix.FAN_EVENT_INFO_TYPE_ERROR:
		return "ERROR"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

func maskNames(m uint64) string {
	names := []struct {
		bit uint64
		s   string
	}{
		{unix.FAN_CREATE, "CREATE"}, {unix.FAN_MODIFY, "MODIFY"},
		{unix.FAN_CLOSE_WRITE, "CLOSE_WRITE"}, {unix.FAN_CLOSE_NOWRITE, "CLOSE_NOWRITE"},
		{unix.FAN_OPEN, "OPEN"}, {unix.FAN_ACCESS, "ACCESS"},
		{unix.FAN_DELETE, "DELETE"}, {unix.FAN_MOVED_FROM, "MOVED_FROM"},
		{unix.FAN_MOVED_TO, "MOVED_TO"}, {unix.FAN_ATTRIB, "ATTRIB"},
		{unix.FAN_ONDIR, "ONDIR"},
	}
	out := ""
	for _, n := range names {
		if m&n.bit != 0 {
			if out != "" {
				out += "|"
			}
			out += n.s
		}
	}
	if out == "" {
		out = fmt.Sprintf("0x%x", m)
	}
	return out
}

type mode struct {
	name      string
	initFlags uint
	markMask  uint64
}

func main() {
	dir, err := os.MkdirTemp("", "t005-*")
	if err != nil {
		fmt.Println("mkdtemp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	fmt.Printf("kernel: %s\nwatch dir: %s\n\n", kernelRelease(), dir)

	modes := []mode{
		{
			name:      "CLASS_NOTIF (classic, fd-per-event)",
			initFlags: unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC,
			markMask:  unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN,
		},
		{
			name:      "CLASS_NOTIF|REPORT_FID",
			initFlags: unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_FID,
			markMask:  unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_CREATE,
		},
		{
			name:      "CLASS_NOTIF|REPORT_DFID_NAME",
			initFlags: unix.FAN_CLASS_NOTIF | unix.FAN_CLOEXEC | unix.FAN_REPORT_DFID_NAME,
			markMask:  unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_CREATE,
		},
		{
			name:      "CLASS_CONTENT (blocking / permission events)",
			initFlags: unix.FAN_CLASS_CONTENT | unix.FAN_CLOEXEC,
			markMask:  unix.FAN_OPEN_PERM,
		},
	}

	for _, m := range modes {
		sub, err := os.MkdirTemp(dir, "mode-*")
		if err != nil {
			fmt.Println("mkdtemp:", err)
			continue
		}
		probe(m, sub)
	}
}

func probe(m mode, dir string) {
	fmt.Printf("=== %s ===\n", m.name)

	fd, err := unix.FanotifyInit(m.initFlags, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		fmt.Printf("  fanotify_init: FAILED — %v\n\n", err)
		return
	}
	defer unix.Close(fd)
	fmt.Printf("  fanotify_init: ok\n")

	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, m.markMask, unix.AT_FDCWD, dir); err != nil {
		fmt.Printf("  fanotify_mark:  FAILED — %v\n\n", err)
		return
	}
	fmt.Printf("  fanotify_mark:  ok\n")

	// Generate activity for the listener to observe.
	go func() {
		time.Sleep(80 * time.Millisecond)
		p := filepath.Join(dir, "customers.csv")
		_ = os.WriteFile(p, []byte("name,cpf\nalice,11144477735\n"), 0o600)
		if f, err := os.Open(p); err == nil {
			_ = f.Close()
		}
	}()

	buf := make([]byte, 8192)
	deadline := time.Now().Add(1500 * time.Millisecond)
	seen := 0

	for time.Now().Before(deadline) && seen < 3 {
		if err := waitReadable(fd, 400*time.Millisecond); err != nil {
			fmt.Printf("  poll: %v\n", err)
			break
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			fmt.Printf("  read: FAILED — %v\n", err)
			break
		}
		if n <= 0 {
			fmt.Printf("  read: returned %d bytes\n", n)
			break
		}
		for off := 0; off+metadataLen <= n; {
			meta := (*eventMetadata)(unsafe.Pointer(&buf[off]))
			if meta.EventLen < metadataLen || off+int(meta.EventLen) > n {
				break
			}
			seen++
			fmt.Printf("  event: mask=%-24s pid=%d fd=%d len=%d\n",
				maskNames(meta.Mask), meta.Pid, meta.Fd, meta.EventLen)

			describeIdentity(meta, buf[off:off+int(meta.EventLen)])

			// Permission events must be answered or the writer stays blocked in
			// TASK_UNINTERRUPTIBLE. Always allow — this spike observes only.
			if meta.Mask&unix.FAN_OPEN_PERM != 0 && meta.Fd >= 0 {
				resp := make([]byte, 8)
				binary.LittleEndian.PutUint32(resp[0:], uint32(meta.Fd))
				binary.LittleEndian.PutUint32(resp[4:], unix.FAN_ALLOW)
				_, _ = unix.Write(fd, resp)
			}
			if meta.Fd >= 0 {
				_ = unix.Close(int(meta.Fd))
			}
			off += int(meta.EventLen)
		}
	}
	if seen == 0 {
		fmt.Printf("  (no events observed)\n")
	}
	fmt.Println()
}

// describeIdentity answers the question the schema needs: given an event, how
// is the file identified, and can that identity be turned into a path?
func describeIdentity(meta *eventMetadata, ev []byte) {
	if meta.Fd >= 0 {
		// Classic mode: the kernel hands over an open descriptor. The path is
		// one readlink away and needs no extra capability.
		link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
		if err != nil {
			fmt.Printf("    identity: fd=%d, readlink FAILED: %v\n", meta.Fd, err)
		} else {
			fmt.Printf("    identity: fd -> RESOLVED PATH %q (no extra capability needed)\n", link)
		}
		return
	}

	// FID modes: no descriptor. Walk the info records.
	off := int(meta.MetadataLen)
	if off < metadataLen {
		off = metadataLen
	}
	found := false
	for off+4 <= len(ev) {
		h := (*infoHeader)(unsafe.Pointer(&ev[off]))
		if h.Len == 0 || off+int(h.Len) > len(ev) {
			break
		}
		found = true
		rec := ev[off : off+int(h.Len)]
		switch h.InfoType {
		case unix.FAN_EVENT_INFO_TYPE_FID, unix.FAN_EVENT_INFO_TYPE_DFID:
			fmt.Printf("    identity: %s record (%d bytes) — opaque handle, NO path\n",
				infoTypeName(h.InfoType), h.Len)
			tryOpenByHandle(rec)
		case unix.FAN_EVENT_INFO_TYPE_DFID_NAME:
			// header(4) + fsid(8) + file_handle{bytes(4),type(4),handle[]} then NUL-terminated name
			name := extractName(rec)
			fmt.Printf("    identity: DFID_NAME record — parent handle + name %q\n", name)
			fmt.Printf("              -> path reconstructable as <watched-dir>/%s WITHOUT extra capability\n", name)
		default:
			fmt.Printf("    identity: %s record (%d bytes)\n", infoTypeName(h.InfoType), h.Len)
		}
		off += int(h.Len)
	}
	if !found {
		fmt.Printf("    identity: NONE — no fd and no info record\n")
	}
}

// tryOpenByHandle attempts to turn an opaque handle back into something we can
// read, which is what classification would need. Measured rather than assumed.
func tryOpenByHandle(rec []byte) {
	const fixed = 4 + 8 // info header + fsid
	if len(rec) < fixed+8 {
		fmt.Printf("              -> record too short to parse handle\n")
		return
	}
	mountFd := unix.AT_FDCWD
	hb := binary.LittleEndian.Uint32(rec[fixed:])
	ht := int32(binary.LittleEndian.Uint32(rec[fixed+4:]))
	raw := rec[fixed+8:]
	if int(hb) > len(raw) {
		fmt.Printf("              -> handle_bytes=%d exceeds record\n", hb)
		return
	}
	h := unix.NewFileHandle(ht, raw[:hb])
	fd, err := unix.OpenByHandleAt(mountFd, h, unix.O_RDONLY)
	if err != nil {
		fmt.Printf("              -> open_by_handle_at: FAILED — %v\n", err)
		fmt.Printf("                 (expected without CAP_DAC_READ_SEARCH; the shipped agent has it)\n")
		return
	}
	defer unix.Close(fd)
	link, lerr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if lerr != nil {
		fmt.Printf("              -> open_by_handle_at: OK, readlink failed: %v\n", lerr)
		return
	}
	fmt.Printf("              -> open_by_handle_at: OK -> RESOLVED PATH %q\n", link)
}

// extractName pulls the trailing NUL-terminated filename out of a DFID_NAME record.
func extractName(rec []byte) string {
	const fixed = 4 + 8 + 8 // info header + fsid + file_handle{handle_bytes,handle_type}
	if len(rec) <= fixed {
		return ""
	}
	hb := int(binary.LittleEndian.Uint32(rec[12:16])) // file_handle.handle_bytes
	start := fixed + hb
	if start >= len(rec) {
		return ""
	}
	nameBytes := rec[start:]
	for i, b := range nameBytes {
		if b == 0 {
			return string(nameBytes[:i])
		}
	}
	return string(nameBytes)
}

func waitReadable(fd int, d time.Duration) error {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, int(d.Milliseconds()))
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("timeout")
	}
	return nil
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	b := u.Release[:]
	for i, c := range b {
		if c == 0 {
			b = b[:i]
			break
		}
	}
	return string(b)
}
