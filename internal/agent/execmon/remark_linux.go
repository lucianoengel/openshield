//go:build linux

package execmon

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// WatchForNewExecutables marks binaries that appear in the watched directories after startup.
//
// IT IS NOT AN OPTIMISATION, IT IS WHAT MAKES THE NARROWING SAFE. A per-file mark covers what existed
// when it was applied; under default-deny an unmarked binary produces no permission event and therefore
// RUNS. So a naive narrowing does not merely miss a file — it hands an attacker a better outcome than
// being allowed, because the execution is invisible. Dropping a binary into a watched directory has to
// keep working exactly as it did under the mount mark.
//
// Marking happens on CREATE, MOVED_TO and CLOSE_WRITE. Close-after-write matters because a file is
// typically created empty and made executable later — marking only on create would mark something that
// is not yet a binary and never re-mark it once it is.
//
// RESIDUAL RACE, stated rather than hidden: a binary created and executed before the watcher's mark
// lands escapes the gate. The window is bounded by scheduler latency between the inotify event and the
// fanotify mark, which is far smaller than the alternative failure (an operator noticing) — but it is
// not zero, and an operator writing a security case on this should know it.
//
// It is parser-free by construction: inotify records are a fixed-shape kernel struct read with
// encoding/binary-free arithmetic, which is the same discipline the exec IPC transport follows.
func (m *Monitor) WatchForNewExecutables(ctx context.Context, onErr func(error)) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	const mask = unix.IN_CREATE | unix.IN_MOVED_TO | unix.IN_CLOSE_WRITE
	wd := map[int32]string{}
	addDir := func(dir string) {
		w, err := unix.InotifyAddWatch(fd, dir, mask)
		if err != nil {
			if onErr != nil {
				onErr(err)
			}
			return
		}
		wd[int32(w)] = dir
	}
	// Watch every directory in the tree: a per-file mark does not cover a nested directory, so neither
	// does watching only the root.
	for _, root := range m.watched {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				addDir(p)
			}
			return nil
		})
	}

	go func() {
		<-ctx.Done()
		_ = unix.Close(fd) // unblocks the read below
	}()

	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil || n <= 0 {
			return ctx.Err()
		}
		for off := 0; off+16 <= n; {
			// struct inotify_event { int wd; uint32 mask; uint32 cookie; uint32 len; char name[]; }
			w := int32(u32(buf[off:]))
			evMask := u32(buf[off+4:])
			nameLen := int(u32(buf[off+12:]))
			nameStart := off + 16
			if nameStart+nameLen > n {
				break
			}
			name := trimNUL(buf[nameStart : nameStart+nameLen])
			off = nameStart + nameLen

			dir, ok := wd[w]
			if !ok || name == "" {
				continue
			}
			p := filepath.Join(dir, name)
			info, err := os.Stat(p)
			if err != nil {
				continue
			}
			if info.IsDir() {
				addDir(p) // a new subdirectory must be watched, or binaries inside it are invisible
				continue
			}
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				continue // not executable (yet) — CLOSE_WRITE will bring it back when it is
			}
			if err := m.MarkFile(p); err != nil && onErr != nil {
				onErr(err)
			}
			_ = evMask
		}
	}
}

func u32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func trimNUL(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
