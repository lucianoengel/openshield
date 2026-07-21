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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	enrollpkg "github.com/lucianoengel/openshield/internal/agent/enroll"
	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/retain"
	"github.com/lucianoengel/openshield/internal/store/postgres"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"github.com/nats-io/nats.go"
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

	// Enforce local-ledger retention on a timer (D81): tombstone bounded-class
	// entries past their age so content is erased while the hash chain stays
	// verifiable (D36). The Purge exists (T-013) but was never scheduled (D20).
	go retain.Loop(ctx, envDuration("OPENSHIELD_RETENTION_INTERVAL", 24*time.Hour), func(ctx context.Context) {
		n, err := ledger.Purge(ctx, time.Now())
		if err != nil {
			log.Error("retention purge failed", slog.String("err", err.Error()))
			return
		}
		if n > 0 {
			log.Info("retention purge tombstoned entries", slog.Int64("rows", n))
		}
	})

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

	// Zero-Trust ACCESS MODE (D90): a gateway runs as EITHER an egress forward proxy
	// (below) OR a client-cert access proxy — different roles, different ports. When
	// OPENSHIELD_ACCESS_MODE is set, run the access proxy and return.
	if os.Getenv("OPENSHIELD_ACCESS_MODE") != "" {
		runAccessMode(ctx, log, pool, ledger)
		return
	}

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

		// SIGHUP hot-rotates the interception CA without a restart (D79): reload the
		// CA files and Rotate. A reload error is logged and the old CA keeps serving
		// (fail-safe) — a bad rotation must not break interception.
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				nc, err1 := os.ReadFile(caCert)
				nk, err2 := os.ReadFile(caKey)
				if err1 != nil || err2 != nil {
					log.Error("gateway: CA reload read failed (old CA still serving)", slog.Any("cert_err", err1), slog.Any("key_err", err2))
					continue
				}
				if err := minter.Rotate(nc, nk); err != nil {
					log.Error("gateway: interception CA rotation failed (old CA still serving)", slog.String("err", err.Error()))
					continue
				}
				log.Warn("gateway: interception CA ROTATED (SIGHUP) — leaf cache flushed (D79)")
			}
		}()
	}

	// OPTIONAL telemetry projection to the control plane (D77): when NATS + an
	// enrollment endpoint are configured, enroll a signed identity and project a
	// boundary-safe view of decisions. Off by default; the local ledger is always
	// the system of record.
	if natsURL, enrollURL := os.Getenv("OPENSHIELD_NATS_URL"), os.Getenv("OPENSHIELD_ENROLL_URL"); natsURL != "" && enrollURL != "" {
		agentID := env("OPENSHIELD_AGENT_ID", "gateway")
		id, err := identity.Generate(agentID)
		if err != nil {
			fatal(log, "identity", err)
		}
		if err := enrollpkg.Enroll(ctx, http.DefaultClient, enrollURL, agentID, os.Getenv("OPENSHIELD_ENROLL_TOKEN"), id); err != nil {
			fatal(log, "enroll", err)
		}
		conn, err := nats.Connect(natsURL)
		if err != nil {
			fatal(log, "nats", err)
		}
		defer conn.Close()
		var pub *natsx.SignedPublisher
		if seqFile := os.Getenv("OPENSHIELD_SEQ_FILE"); seqFile != "" {
			pub, err = natsx.NewSignedPublisherWithSeq(agentID, id, conn, natsx.NewFileSeqStore(seqFile))
			if err != nil {
				fatal(log, "sequence store", err)
			}
		} else {
			pub = natsx.NewSignedPublisher(agentID, id, conn)
		}
		gw.SetTelemetry(pub)
		log.Info("gateway: telemetry projection ENABLED (boundary-safe: no user IP, no URL path)",
			slog.String("agent_id", agentID))
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

// runAccessMode serves the Zero-Trust access proxy (D90): the AccessProxy over
// client-certificate-required TLS, with a file-loaded default-deny access policy, an
// env service catalog, and a RiskStore. Config is fail-fast and LOUD — a ZT gate must
// never boot misconfigured and permissive; the failure mode is "does not start",
// never "starts and admits everyone".
func runAccessMode(ctx context.Context, log *slog.Logger, cls *privileged.Pool, ledger core.Ledger) {
	listen := env("OPENSHIELD_ACCESS_LISTEN", "127.0.0.1:8443")
	clientCA := os.Getenv("OPENSHIELD_ACCESS_CLIENT_CA")
	serverCert := os.Getenv("OPENSHIELD_ACCESS_SERVER_CERT")
	serverKey := os.Getenv("OPENSHIELD_ACCESS_SERVER_KEY")
	policyPath := os.Getenv("OPENSHIELD_ACCESS_POLICY")

	if clientCA == "" || serverCert == "" || serverKey == "" || policyPath == "" {
		fatal(log, "access mode", errNoAccessConfig)
	}

	// The access policy is identity-aware and DEFAULT-DENY (D87) — only the operator
	// can author it. Load it, or abort: never fall back to the observe-first default
	// (which is default-ALLOW and would admit everyone).
	mod, err := os.ReadFile(policyPath)
	if err != nil {
		fatal(log, "reading access policy", err)
	}
	accessPol, err := policy.New(ctx, "access", "1", string(mod))
	if err != nil {
		fatal(log, "access policy", err)
	}

	catalog, err := gateway.ParseCatalog(os.Getenv("OPENSHIELD_ACCESS_CATALOG"))
	if err != nil {
		fatal(log, "access catalog", err)
	}
	if catalog.Len() == 0 {
		fatal(log, "access catalog", errEmptyCatalog)
	}

	caPEM, err := os.ReadFile(clientCA)
	if err != nil {
		fatal(log, "reading client CA", err)
	}
	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM(caPEM) {
		fatal(log, "client CA", errNoCerts)
	}
	kp, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		fatal(log, "access server certificate", err)
	}

	gw := gateway.New(cls, accessPol, ledger, log, 30*time.Second)
	ap := gateway.NewAccessProxy(gw, catalog, gateway.DefaultMaxBody, log)
	riskStore := gateway.NewRiskStore()
	ap.SetRiskStore(riskStore)
	postureStore := gateway.NewPostureStore()
	ap.SetPostureStore(postureStore)

	// Subscribe to published risk (D91) and device posture (D92). When NATS is
	// configured, the control plane's per-subject risk updates and the endpoints'
	// posture updates populate the stores. Without NATS both stay empty: a risk-gating
	// policy allows on absent risk (D89), but a posture-requiring policy DENIES on
	// absent posture (D85 tamper-lockout) — the two fail in opposite directions.
	if natsURL := os.Getenv("OPENSHIELD_NATS_URL"); natsURL != "" {
		conn, err := nats.Connect(natsURL)
		if err != nil {
			fatal(log, "risk nats", err)
		}
		defer conn.Close()
		if _, err := gateway.SubscribeRisk(conn, riskStore); err != nil {
			fatal(log, "risk subscribe", err)
		}
		if _, err := gateway.SubscribePosture(conn, postureStore); err != nil {
			fatal(log, "posture subscribe", err)
		}
		log.Info("gateway: risk + device-posture subscriptions active (D91/D92)")
	}

	srv := &http.Server{
		Addr: listen, Handler: ap, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{kp},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientPool,
			MinVersion:   tls.VersionTLS12,
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Warn("gateway: ZERO-TRUST ACCESS MODE — a valid client certificate is REQUIRED (D86/D90)",
		slog.String("listen", listen), slog.Int("services", catalog.Len()))
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		fatal(log, "access serving", err)
	}
	log.Info("gateway access mode shut down")
}

var (
	errNoAccessConfig = errors.New("access mode requires OPENSHIELD_ACCESS_CLIENT_CA, _SERVER_CERT, _SERVER_KEY, and _POLICY")
	errEmptyCatalog   = errors.New("OPENSHIELD_ACCESS_CATALOG is empty — an access gateway must front at least one service")
	errNoCerts        = errors.New("no certificates in OPENSHIELD_ACCESS_CLIENT_CA")
)

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

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
