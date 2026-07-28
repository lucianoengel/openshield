# Design

## A reader that does not end, rather than a loop that restarts

The scanner's contract stays exactly as it is: give it an `io.Reader`, it pairs SYSCALL+EXECVE records
and emits events until the reader is done. Changing that loop to know about files would put log-rotation
logic inside a record parser.

Instead the ENGINE supplies a reader that does not reach EOF while the context is live: on a zero-byte
read it waits and tries again. The scanner is unchanged and untouched, which also means its existing
tests keep testing the thing they were written for.

## Truncation and rotation

Two cases, distinguished by comparing the file's current size against the offset already consumed:

- **Size < offset** — the file was truncated in place (`> file`, or a rotator that copies and
  truncates). Resume from 0; the content is new.
- **The path now names a different inode** — the file was renamed away and recreated. Reopen it.

Both are best-effort and both can lose records written to the old file between the final read and the
rename. That is a real bound, stated in the proposal, not designed away — a tailer that claimed
lossless rotation would be making a promise the filesystem does not offer.

## Why a fifo is left alone

A fifo already blocks rather than returning EOF while a writer holds it open, so the current behaviour
is correct for the documented deployment. Wrapping it in the follower would change nothing except add
a poll to a path that already blocks correctly. The follower is applied when the source is a regular
file — which is the case that is silently broken today.

When a fifo's last writer closes, it DOES return EOF, and that is a real end-of-source: the new
warning covers it.

## Saying that the source ended

`execSource` returning `nil` currently means both "the context was cancelled" (a clean shutdown) and
"the stream ended" (a loss of visibility). Those need to be distinguishable, because one is normal and
the other means the endpoint has stopped reporting executions while the process keeps running.

Shutdown stays silent. An end-of-source while the engine is still running is a WARN naming what was
lost — the same rule the syslog stream listener and the DNS connector already follow: a control that
stops must not stop quietly.

## What the test has to establish

Not "the connector parsed a record" — the existing unit tests cover parsing. The scenario has to prove
the thing that was broken: **a record appended AFTER the engine started is ingested.** Writing the
records before startup would pass against the old code, which is exactly how this defect survived.

And it has to prove the negative is real: with following removed, the appended record must NOT arrive.
