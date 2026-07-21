// Command openshield-engine runs the endpoint pipeline (the walking skeleton).
//
// It is the THIRD endpoint component: unprivileged and network-capable, holding
// what neither the privileged fanotify agent (no OPA — encoding/json is banned
// there, D29) nor the sandboxed worker (no network — seccomp, D35) can. It
// classifies via the worker, evaluates the local policy, and appends to the
// local forward-secure audit ledger. The privileged agent forwards fanotify
// events to it; observe-only (D1) — it records, it does not enforce.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
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
	_ = eng

	log.Info("engine ready", slog.String("worker", workerBin))
	// Phase 1: events are forwarded by the privileged fanotify agent (a thin,
	// privilege-gated step). Until that wire lands, the engine idles here; the
	// walking skeleton is exercised end to end by the tests. Block until signal.
	<-ctx.Done()
	log.Info("engine shut down")
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
