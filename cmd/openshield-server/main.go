// Command openshield-server is the control plane (T-023).
//
// It subscribes to the agent telemetry subjects over NATS and persists what it
// receives to the fleet aggregate store. It coordinates and observes; it does
// NOT distribute policy or control agents (D14). The evidentiary record is the
// agent's local forward-secure ledger, NOT this aggregate.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
	"github.com/lucianoengel/openshield/internal/retain"
	"github.com/lucianoengel/openshield/internal/store/postgres"
	"github.com/lucianoengel/openshield/internal/transport/tlsconf"
)

func main() {
	dsn := env("OPENSHIELD_DSN", "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable")
	// Operator-local subcommands (issuance/revocation are NOT network endpoints, D51).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "issue-token":
			os.Exit(issueToken(dsn, os.Args[2:]))
		case "revoke":
			os.Exit(revokeAgent(dsn, os.Args[2:]))
		case "migrate":
			os.Exit(runMigrate(dsn))
		}
	}
	natsURL := env("OPENSHIELD_NATS_URL", "nats://127.0.0.1:4222")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fatal("connecting to Postgres: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fatal("Postgres unreachable: %v", err)
	}
	if err := postgres.MigrateIfNeeded(ctx, pool); err != nil {
		fatal("migrating: %v", err)
	}

	srv := controlplane.New(pool)

	// Risk-signing key (SEC-1): risk updates published to the gateway MUST be signed with
	// the control-plane key so the gateway can verify they came from here, not a forging
	// publisher. When OPENSHIELD_RISK_SIGNING_KEY is set, load it and enable signed risk
	// publishing; without it, PublishRisk emits nothing (an unsigned update the gateway
	// rejects anyway) — risk continuous-verification stays inert rather than forgeable.
	if kp := os.Getenv("OPENSHIELD_RISK_SIGNING_KEY"); kp != "" {
		key, err := os.ReadFile(kp)
		if err != nil {
			fatal("reading risk signing key: %v", err)
		}
		if len(key) != ed25519.PrivateKeySize {
			fatal("risk signing key is %d bytes, want %d (raw ed25519 private key)", len(key), ed25519.PrivateKeySize)
		}
		srv.SetRiskSigner(ed25519.PrivateKey(key))
		fmt.Fprintf(os.Stderr, "openshield-server: signed risk publishing enabled (SEC-1)\n")
	}

	// PLAT-2b/ADR-3: run the singleton work (telemetry consumer, peer analytics, maintenance loops)
	// under an active-passive leader lease — exactly one instance is leader; a standby waits and takes
	// over on leader failure. A single deployed instance becomes leader immediately (unchanged).
	leader := controlplane.NewLeader(pool)
	_ = leader.Run(ctx, func(leaderCtx context.Context) {
		// Enforce the fleet-aggregate retention window (D81): purge received telemetry
		// and derived peer alerts older than the window, on a timer. The aggregate is a
		// derived view, so this is a hard delete (the evidentiary ledger tombstones
		// instead). Without it, personal-adjacent telemetry accrues forever (D20).
		retInterval := envDuration("OPENSHIELD_RETENTION_INTERVAL", 24*time.Hour)
		fleetRetention := envDuration("OPENSHIELD_FLEET_RETENTION", 90*24*time.Hour)
		go retain.Loop(leaderCtx, retInterval, func(ctx context.Context) {
			n, err := srv.PurgeOlderThan(ctx, time.Now().Add(-fleetRetention))
			if err != nil {
				fmt.Fprintf(os.Stderr, "openshield-server: retention purge failed: %v\n", err)
				return
			}
			fmt.Fprintf(os.Stderr, "openshield-server: retention purge removed %d fleet-aggregate rows\n", n)
		})

		// Alert delivery (D83): when OPENSHIELD_ALERT_WEBHOOK is set, deliver peer-UEBA
		// alerts and overdue-agent alerts to a webhook so a human is TOLD, not left to
		// poll. Best-effort — a down sink never breaks ingest. Overdue notifications are
		// deduplicated (once per silence) and run on a timer.
		if hook := os.Getenv("OPENSHIELD_ALERT_WEBHOOK"); hook != "" {
			// SIEM-8: wrap EACH webhook in bounded retry so a transient blip (a 5xx, a timeout during
			// a deploy) does not silently drop the page (a 4xx is not retried, see notify.Permanent),
			// then fan out to all of them via Multi — the retry is INNER so a retry re-attempts only the
			// failed sink, never re-paging a sink that already succeeded. OPENSHIELD_ALERT_WEBHOOK may be
			// a comma-separated list; OPENSHIELD_ALERT_WEBHOOK_SECRET (optional) HMAC-signs each body so a
			// receiver can verify the alert came from this control plane (unset = unsigned, unchanged).
			attempts := envInt("OPENSHIELD_ALERT_RETRIES", 3)
			secret := []byte(os.Getenv("OPENSHIELD_ALERT_WEBHOOK_SECRET"))
			var sinks []notify.Notifier
			for _, u := range strings.Split(hook, ",") {
				u = strings.TrimSpace(u)
				if u == "" {
					continue
				}
				w := notify.NewWebhook(u)
				if len(secret) > 0 {
					w.Secret = secret
				}
				sinks = append(sinks, notify.NewRetrying(w, attempts, 200*time.Millisecond))
			}
			srv.SetNotifier(notify.NewMulti(sinks...))
			overdueThreshold := envDuration("OPENSHIELD_OVERDUE_THRESHOLD", 15*time.Minute)
			overdueInterval := envDuration("OPENSHIELD_OVERDUE_INTERVAL", 5*time.Minute)
			go retain.Loop(leaderCtx, overdueInterval, func(ctx context.Context) {
				if n, err := srv.NotifyOverdue(ctx, overdueThreshold); err != nil {
					fmt.Fprintf(os.Stderr, "openshield-server: overdue check failed: %v\n", err)
				} else if n > 0 {
					fmt.Fprintf(os.Stderr, "openshield-server: notified %d newly-overdue agent(s)\n", n)
				}
			})
			fmt.Fprintf(os.Stderr, "openshield-server: alert delivery enabled (webhook)\n")
		}

		// Server-side peer-UEBA (D54), OFF unless a threshold is configured — enabling
		// it is the operator's D23 consent/DPIA decision, never a default. It observes
		// the verified fleet stream and records peer alerts; it does not control agents.
		peerUEBAEnabled := false
		if v := os.Getenv("OPENSHIELD_PEER_UEBA_THRESHOLD"); v != "" {
			threshold, err := strconv.ParseFloat(v, 64)
			if err != nil {
				fatal("OPENSHIELD_PEER_UEBA_THRESHOLD=%q: %v", v, err)
			}
			cooldown := 1 * time.Hour
			if c := os.Getenv("OPENSHIELD_PEER_UEBA_COOLDOWN"); c != "" {
				if d, err := time.ParseDuration(c); err == nil {
					cooldown = d
				}
			}
			srv.EnablePeerUEBA(threshold, cooldown)
			peerUEBAEnabled = true
			fmt.Fprintf(os.Stderr, "openshield-server: peer-UEBA enabled (threshold %.2f, cooldown %s)\n", threshold, cooldown)

			// SIEM-5: persist the baseline periodically so a restart resumes it (EnablePeerUEBA
			// reloads it). Best-effort — a failed persist only shortens the next restart's warm
			// window, never breaks ingest. A final persist on shutdown runs after Run returns.
			persistInterval := envDuration("OPENSHIELD_UEBA_PERSIST_INTERVAL", 5*time.Minute)
			go retain.Loop(leaderCtx, persistInterval, func(ctx context.Context) {
				if err := srv.PersistBaselines(ctx); err != nil {
					fmt.Fprintf(os.Stderr, "openshield-server: peer-UEBA baseline persist failed: %v\n", err)
				}
			})
		}

		// Mutual TLS on the agent-facing channels (D55), OFF unless configured —
		// enabling it is a deliberate deployment step. A partial or unreadable
		// configuration fails loudly here, never silently to plaintext.
		tlsConf, err := tlsconf.LoadFromEnv()
		if err != nil {
			fatal("TLS configuration: %v", err)
		}
		if tlsConf != nil {
			// This presents a client cert and verifies the NATS server's cert against
			// the CA. It does NOT make the broker demand a client cert from AGENTS —
			// that is the broker's own `--tlsverify --tlscacert`, a DEPLOYMENT
			// requirement (D55). Without it, mutual auth on the telemetry leg does not
			// hold even though this logs "enabled"; D50 signing still protects evidence.
			srv.SetNATSOptions(nats.Secure(tlsConf.ClientConfig()))
			fmt.Fprintln(os.Stderr, "openshield-server: mutual TLS enabled on the enrollment endpoint; "+
				"NATS mutual auth requires the broker's --tlsverify (D55)")
		}

		// Optional enrollment endpoint (D44 over the wire). Served over mutual TLS
		// when configured; the token travels in the body. Token issuance is NOT
		// exposed — an admin-local operation.
		if addr := os.Getenv("OPENSHIELD_HTTP_ADDR"); addr != "" {
			go func() {
				fmt.Fprintf(os.Stderr, "openshield-server: enrollment endpoint on %s\n", addr)
				var serveErr error
				if tlsConf != nil {
					serveErr = srv.ServeHTTPTLS(leaderCtx, addr, tlsConf.ServerConfig())
				} else {
					serveErr = srv.ServeHTTP(leaderCtx, addr)
				}
				if serveErr != nil {
					fmt.Fprintf(os.Stderr, "openshield-server: enrollment endpoint: %v\n", serveErr)
				}
			}()
		}

		// Optional Prometheus metrics endpoint (PLAT-4), on a SEPARATE address — the "no silent
		// loss" counters (dropped/rejected/gapped telemetry) so an operator can alert on them.
		// Unauthenticated by convention (a scrape target); put it on an internal/firewalled addr.
		if maddr := os.Getenv("OPENSHIELD_METRICS_ADDR"); maddr != "" {
			// PLAT-4b: /metrics leaks fleet operational tempo (rejected/gapped-telemetry counts reveal
			// replay-attempt recon). Require a bearer token when OPENSHIELD_METRICS_TOKEN is set, and
			// warn LOUDLY if bound beyond loopback without one — a scrape target on a public interface
			// with no auth is a reconnaissance surface.
			var metricsHandler http.Handler = srv.MetricsHandler()
			hasToken := false
			if tok := os.Getenv("OPENSHIELD_METRICS_TOKEN"); tok != "" {
				metricsHandler = controlplane.RequireBearerToken(tok, metricsHandler)
				hasToken = true
				fmt.Fprintln(os.Stderr, "openshield-server: metrics endpoint requires a bearer token (PLAT-4b)")
			}
			if controlplane.IsNonLoopbackBind(maddr) && !hasToken {
				fmt.Fprintf(os.Stderr, "openshield-server: WARNING — metrics endpoint bound to a NON-LOOPBACK "+
					"address %q with NO auth; this leaks fleet operational tempo (replay recon). Bind to "+
					"loopback or set OPENSHIELD_METRICS_TOKEN.\n", maddr)
			}
			mux := http.NewServeMux()
			mux.Handle("/metrics", metricsHandler)
			msrv := &http.Server{Addr: maddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
			go func() {
				fmt.Fprintf(os.Stderr, "openshield-server: metrics endpoint on %s/metrics\n", maddr)
				if err := msrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					fmt.Fprintf(os.Stderr, "openshield-server: metrics endpoint: %v\n", err)
				}
			}()
			go func() { <-leaderCtx.Done(); _ = msrv.Close() }()
		}

		fmt.Fprintf(os.Stderr, "openshield-server: subscribing to telemetry on %s\n", natsURL)
		if err := srv.Run(leaderCtx, natsURL); err != nil && leaderCtx.Err() == nil {
			fatal("control plane: %v", err)
		}
		// SIEM-5: a final baseline persist on shutdown, so a clean restart resumes the freshest
		// baseline. ctx is already cancelled here (shutdown), so use a short fresh deadline.
		if peerUEBAEnabled {
			pctx, pcancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := srv.PersistBaselines(pctx); err != nil {
				fmt.Fprintf(os.Stderr, "openshield-server: final peer-UEBA baseline persist failed: %v\n", err)
			}
			pcancel()
		}
	})
	fmt.Fprintln(os.Stderr, "openshield-server: shut down")
}

// runMigrate applies migrations as the OWNER and provisions the non-owner application LOGIN role
// (PLAT-6b). The deploy runs this once with the owner DSN; the app binaries then connect as the
// provisioned non-owner role (fullyMigrated lets them skip Migrate). Provisioning is skipped when
// no OPENSHIELD_APP_PASSWORD is set, so a dev that runs everything as the owner is unaffected.
func runMigrate(dsn string) int {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		return 1
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		return 1
	}
	role := env("OPENSHIELD_APP_ROLE", "openshield_app")
	pass := os.Getenv("OPENSHIELD_APP_PASSWORD")
	if pass == "" {
		fmt.Fprintln(os.Stderr, "migrate: schema up to date; OPENSHIELD_APP_PASSWORD unset, skipping non-owner app-role provisioning")
		return 0
	}
	if err := postgres.EnsureAppLogin(ctx, pool, role, pass); err != nil {
		fmt.Fprintln(os.Stderr, "migrate: provisioning app role:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "migrate: schema up to date; provisioned non-owner app role %q\n", role)
	return 0
}

func issueToken(dsn string, args []string) int {
	ttl := 3600
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil {
			ttl = v
		}
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue-token:", err)
		return 1
	}
	defer pool.Close()
	if err := postgres.MigrateIfNeeded(ctx, pool); err != nil {
		fmt.Fprintln(os.Stderr, "issue-token migrate:", err)
		return 1
	}
	tok, err := controlplane.New(pool).IssueToken(ctx, time.Duration(ttl)*time.Second, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue-token:", err)
		return 1
	}
	fmt.Println(tok)
	return 0
}

func revokeAgent(dsn string, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: openshield-server revoke <agent-id>")
		return 2
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		return 1
	}
	defer pool.Close()
	if err := controlplane.New(pool).Revoke(ctx, args[0], time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "revoke:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "revoked %s\n", args[0])
	return 0
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "openshield-server: "+format+"\n", args...)
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

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
