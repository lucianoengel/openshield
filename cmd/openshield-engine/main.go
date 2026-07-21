// Command openshield-engine runs the endpoint pipeline (the walking skeleton).
//
// It is unprivileged and network-capable, holding what the sandboxed worker (no
// network — seccomp, D35) cannot: OPA (encoding/json, D29) and the Postgres
// ledger. For the OBSERVE path it also opens the fanotify connector itself —
// notify mode needs no privilege (D52) — watches OPENSHIELD_WATCH_DIRS, and runs
// each event through classify → policy → decide → audit. Observe-only (D1): it
// records, it does not enforce. Inline blocking (the privileged permission-mode
// agent) is a separate, deferred component (D49).
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/connectors/fanotify"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	dsn := env("OPENSHIELD_DSN", "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable")
	workerBin := env("OPENSHIELD_WORKER_BIN", "/usr/local/bin/openshield-worker")
	signerFile := env("OPENSHIELD_SIGNER_FILE", "/var/lib/openshield/signer.state")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Validate the watch configuration FIRST — an engine watching nothing is a
	// silent no-op (the failure D17 forbids in spirit), and there is no point
	// opening the ledger or the worker for it.
	dirs := watchDirs()
	if len(dirs) == 0 {
		fatal(log, "no watch directories", errNoWatchDirs)
	}

	// The signer: reload it (write-resume, D46) or create and persist a new one.
	signer, err := loadOrCreateSigner(signerFile, log)
	if err != nil {
		fatal(log, "signer", err)
	}

	ledger, err := postgres.Open(ctx, dsn, signer)
	if err != nil {
		fatal(log, "opening ledger", err)
	}
	defer ledger.Close()

	pol, err := policy.NewDefault(ctx)
	if err != nil {
		fatal(log, "loading policy", err)
	}

	worker, err := privileged.StartWorker(ctx, workerBin)
	if err != nil {
		fatal(log, "starting worker", err)
	}
	defer worker.Close()

	eng := engine.NewFromWorker(worker, pol, ledger, log, 30*time.Second)

	// The observe path needs no privileged agent: fanotify NOTIFY mode works
	// UNPRIVILEGED (D52). The engine opens the connector itself over the configured
	// directories (validated above) and runs each event through the pipeline.
	// Inline blocking (the privileged permission-mode agent) is deferred (D49).
	events := make(chan *corev1.Event, 64)
	var wg sync.WaitGroup
	opened := 0
	for _, dir := range dirs {
		w, err := fanotify.Open(dir)
		if err != nil {
			log.Error("watch", slog.String("dir", dir), slog.String("err", err.Error()))
			continue
		}
		opened++
		defer w.Close()
		wg.Add(1)
		go watch(ctx, log, w, dir, events, &wg)
	}
	if opened == 0 {
		fatal(log, "opening watchers", errNoWatchDirs)
	}
	go func() { wg.Wait(); close(events) }()

	log.Info("engine observing", slog.String("worker", workerBin), slog.Int("dirs", opened))
	for {
		select {
		case <-ctx.Done():
			log.Info("engine shut down")
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			dec, err := eng.Process(ctx, ev)
			if err != nil {
				// A processing error is auditable, not silent (D17) — the engine's
				// audit sink records the outcome; here we surface it operationally.
				log.Error("process", slog.String("event", ev.GetEventId()), slog.String("err", err.Error()))
				continue
			}
			if dec != nil {
				log.Info("decision",
					slog.String("event", ev.GetEventId()),
					slog.String("action", dec.GetAction().String()),
					slog.String("path", ev.GetFilesystem().GetResolvedPath()))
			}
		}
	}
}

// errNoWatchDirs makes an engine watching nothing fail loudly rather than run as
// a silent no-op.
var errNoWatchDirs = errors.New("set OPENSHIELD_WATCH_DIRS (comma-separated) to at least one directory")

// watchDirs parses OPENSHIELD_WATCH_DIRS (comma-separated), trimming blanks.
func watchDirs() []string {
	var out []string
	for _, d := range strings.Split(os.Getenv("OPENSHIELD_WATCH_DIRS"), ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// watch feeds a directory's fanotify events into the shared channel until the
// context is cancelled. A read error that is not cancellation is logged and the
// watch continues — a transient error must not silently stop observation.
func watch(ctx context.Context, log *slog.Logger, w *fanotify.Watcher, dir string, out chan<- *corev1.Event, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		ev, err := w.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error("watch next", slog.String("dir", dir), slog.String("err", err.Error()))
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return
		}
	}
}

func loadOrCreateSigner(path string, log *slog.Logger) (*core.Signer, error) {
	if s, err := core.LoadSignerFile(path); err == nil {
		log.Info("resumed signer", slog.String("file", path))
		return s, nil
	}
	s, err := core.NewSigner()
	if err != nil {
		return nil, err
	}
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr == nil {
		_ = core.SaveSignerFile(path, s)
	}
	return s, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, slog.String("err", err.Error()))
	os.Exit(1)
}
