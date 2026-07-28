package execaudit

import (
	"context"
	"io"
	"os"
	"time"
)

// Follow turns a regular file into a reader that does not end while ctx is live (HIPS-5c).
//
// WHY THIS EXISTS. The engine used to `os.Open` the configured audit log and hand it straight to the
// scanner, whose loop ends at EOF. Against a regular file — which is exactly what
// `OPENSHIELD_EXEC_AUDIT_LOG` invites, being described as "auditd log the exec connector reads" — that
// meant every execution recorded BEFORE startup was ingested and none after it, while the startup line
// said the connector was enabled. A detector that reports itself on, drains a backlog, and then sees
// nothing is the silent gap D31 forbids, on the endpoint's process-visibility source.
//
// IT IS A READER, NOT A LOOP AROUND THE SCANNER. The scanner's contract — give it an io.Reader, it
// pairs SYSCALL+EXECVE and emits — stays untouched, so log-rotation logic does not end up inside a
// record parser and the scanner's existing tests keep testing what they were written for.
//
// POLLING, NOT INOTIFY, and the delay is real: a record is seen within one interval of being written.
// Acceptable for an observe-only visibility source, and stated rather than hidden because it would
// matter to anything built on top of it.
type follower struct {
	f        *os.File
	path     string
	interval time.Duration
	ctx      context.Context
	offset   int64
}

// FollowInterval is the poll delay. Short enough that an exec is classified promptly, long enough that
// an idle endpoint is not spinning on stat().
const FollowInterval = 250 * time.Millisecond

// Follow wraps an open regular file. The caller keeps ownership of f.
func Follow(ctx context.Context, f *os.File, path string, interval time.Duration) io.Reader {
	if interval <= 0 {
		interval = FollowInterval
	}
	return &follower{f: f, path: path, interval: interval, ctx: ctx}
}

// Read returns appended bytes, waiting rather than reporting EOF.
//
// It returns io.EOF ONLY when the context is done, so the scanner's loop ends on shutdown and at no
// other time.
func (fl *follower) Read(p []byte) (int, error) {
	for {
		n, err := fl.f.Read(p)
		if n > 0 {
			fl.offset += int64(n)
			return n, nil
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		// At the end of the file. Before waiting, check whether the file we are holding is still the
		// file the path names, and whether it shrank underneath us.
		if rerr := fl.reopenIfRotated(); rerr != nil {
			return 0, rerr
		}
		select {
		case <-fl.ctx.Done():
			return 0, io.EOF
		case <-time.After(fl.interval):
		}
	}
}

// reopenIfRotated handles the two ways a log file stops being the one we opened.
//
// Both are best-effort, and both can lose records written to the old file between our last read and
// the rename. That bound is the filesystem's, not something a tailer can close, so it is named here
// rather than claimed away.
func (fl *follower) reopenIfRotated() error {
	st, err := fl.f.Stat()
	if err != nil {
		return nil // transient; try again next tick rather than killing the source
	}
	// TRUNCATED IN PLACE (`> file`, or a rotator that copies then truncates): the content that follows
	// is new, so resume from the start. Detected by the file being SHORTER than what we have consumed.
	if st.Size() < fl.offset {
		if _, serr := fl.f.Seek(0, io.SeekStart); serr == nil {
			fl.offset = 0
		}
		return nil
	}
	// REPLACED (renamed away and recreated): the path now names a different inode. Reopen it, and
	// start at the beginning because the new file's contents have never been read.
	if fl.path == "" {
		return nil
	}
	onDisk, err := os.Stat(fl.path)
	if err != nil {
		return nil // rotator may be mid-rename; keep the current handle and retry
	}
	if os.SameFile(st, onDisk) {
		return nil
	}
	nf, err := os.Open(fl.path)
	if err != nil {
		return nil
	}
	_ = fl.f.Close()
	fl.f = nf
	fl.offset = 0
	return nil
}
