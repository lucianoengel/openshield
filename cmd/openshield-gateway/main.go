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
// classifies, decides and audits but forwards every flow. HTTPS is tunneled blind
// unless an interception CA is configured (OPENSHIELD_INTERCEPT_CA_CERT/KEY, D75),
// in which case non-excluded hosts are TLS-intercepted and their bodies classified;
// the do-not-intercept list (OPENSHIELD_NO_INTERCEPT) tunnels pinned/sensitive
// hosts blind.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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

	poolSize := envInt("OPENSHIELD_WORKER_POOL", 4)
	pool, err := privileged.StartPool(ctx, workerBin, poolSize)
	if err != nil {
		fatal(log, "starting worker pool", err)
	}
	defer pool.Close()

	// The pool satisfies gateway.New's classifier interface (same Classify method as
	// a single worker), so concurrent flows classify in parallel (D76).
	gw := gateway.New(pool, pol, ledger, log, 30*time.Second)
	table := gateway.NewTable()
	proxy := gateway.NewProxy(gw, table, nil, redirectURL, gateway.DefaultMaxBody, enforce, log)

	// TLS interception is OPT-IN: only when an interception CA is configured. It is
	// a deliberate, scary capability — the CA can impersonate any site (D75) — so it
	// is never on by default. The do-not-intercept list tunnels pinned/sensitive
	// hosts blind even when it is on.
	if caCert, caKey := os.Getenv("OPENSHIELD_INTERCEPT_CA_CERT"), os.Getenv("OPENSHIELD_INTERCEPT_CA_KEY"); caCert != "" && caKey != "" {
		certPEM, err := os.ReadFile(caCert)
		if err != nil {
			fatal(log, "reading interception CA cert", err)
		}
		keyPEM, err := os.ReadFile(caKey)
		if err != nil {
			fatal(log, "reading interception CA key", err)
		}
		minter, err := gateway.NewCertMinter(certPEM, keyPEM)
		if err != nil {
			fatal(log, "interception CA", err)
		}
		proxy.EnableInterception(minter, splitList(os.Getenv("OPENSHIELD_NO_INTERCEPT")), nil)
		log.Warn("gateway: TLS INTERCEPTION ENABLED — the interception CA can impersonate any site (D75)",
			slog.Int("do_not_intercept", len(splitList(os.Getenv("OPENSHIELD_NO_INTERCEPT")))))
	}

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
		slog.Bool("intercept", proxy.Intercepting()))
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

// envInt reads an integer env var, falling back to def on absence or a parse error.
func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// splitList parses a comma-separated env value, trimming blanks.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fatal(log *slog.Logger, msg string, err error) {
	log.Error(msg, slog.String("err", err.Error()))
	os.Exit(1)
}
