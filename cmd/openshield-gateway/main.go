// Command openshield-gateway runs the network gateway data plane (N1.2b).
//
// It is a plain-HTTP forward proxy: it accepts a client connection, runs each
// request through the gateway pipeline (classify in the sandboxed worker, D72 →
// policy → decide → audit), and applies the verdict to the live connection —
// forward, block, or redirect. Like the engine (D62) it is unprivileged and
// network-capable, holding the ledger and OPA but NOT the parser: it spawns the
// worker rather than classifying itself, so a parser bug is not an RCE in the
// process holding the network sockets (D72).
//
// Observe-only by DEFAULT (D1): unless OPENSHIELD_ENFORCE is set, the proxy
// classifies, decides and audits but forwards every flow. Plain HTTP only — HTTPS
// bodies are opaque until TLS interception (N1.3).
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	listen := env("OPENSHIELD_LISTEN", "127.0.0.1:8080")
	dsn := env("OPENSHIELD_DSN", "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable")
	workerBin := env("OPENSHIELD_WORKER_BIN", "/usr/local/bin/openshield-worker")
	signerFile := env("OPENSHIELD_SIGNER_FILE", "/var/lib/openshield/gateway-signer.state")
	redirectURL := env("OPENSHIELD_REDIRECT_URL", "https://openshield.invalid/coaching")
	enforce := os.Getenv("OPENSHIELD_ENFORCE") != ""

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	gw := gateway.NewFromWorker(worker, pol, ledger, log, 30*time.Second)
	table := gateway.NewTable()
	proxy := gateway.NewProxy(gw, table, nil, redirectURL, gateway.DefaultMaxBody, enforce, log)

	srv := &http.Server{Addr: listen, Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	log.Info("gateway proxying",
		slog.String("listen", listen),
		slog.String("worker", workerBin),
		slog.Bool("enforce", enforce),
		slog.String("mode", "plain-HTTP forward proxy (TLS interception deferred, N1.3)"))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(log, "serving", err)
	}
	log.Info("gateway shut down")
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
