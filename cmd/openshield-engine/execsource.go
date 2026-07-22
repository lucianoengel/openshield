package main

import (
	"context"
	"io"
	"log/slog"

	"github.com/lucianoengel/openshield/internal/connectors/execaudit"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// execSource reads auditd exec records from r, pairs SYSCALL+EXECVE into ProcessSubject Events, and
// feeds them into the engine's event channel — the exec producer (HIPS-5c). It turns the built
// parser + pairing scanner into a running source, like the DNS source. Reading auditd is a
// deployment concern (a tailed /var/log/audit/audit.log, an audit fifo, or the netlink socket); the
// engine reads from a configured stream. A send races context cancellation so shutdown never blocks.
func execSource(ctx context.Context, r io.Reader, events chan<- *corev1.Event, log *slog.Logger) error {
	sc := execaudit.NewScanner(func(ev *corev1.Event) {
		select {
		case events <- ev:
		case <-ctx.Done():
		}
	})
	err := sc.Scan(ctx, r)
	if d := sc.Dropped(); d > 0 {
		log.Warn("execaudit: dropped records", slog.Int64("dropped", d))
	}
	return err
}
