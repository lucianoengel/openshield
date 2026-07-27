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

	"github.com/lucianoengel/openshield/internal/analytics/beacon"
	"github.com/lucianoengel/openshield/internal/config"
	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/nips"
	"github.com/lucianoengel/openshield/internal/notify"
	"github.com/lucianoengel/openshield/internal/retain"
	"github.com/lucianoengel/openshield/internal/runner"
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
		case "ingest-feed":
			os.Exit(ingestFeed(dsn, os.Args[2:]))
		case "fleet-control":
			os.Exit(fleetControl(dsn, os.Args[2:]))
		case "config":
			os.Exit(showConfig())
		}
	}
	// PLAT-5: validate EVERY declared field before doing anything. A malformed value now fails the boot
	// with a precise, field-scoped error instead of silently falling back to a default — which is how a
	// typo'd OPENSHIELD_CORRELATE_INTERVAL used to disable scheduled correlation with no signal at all.
	if err := serverConfig().Validate(); err != nil {
		fatal("%v", err)
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
	// PLAT-9: report SCHEMA SKEW. `applied > embedded` is what a BINARY ROLLBACK looks like — this
	// process is reading a schema whose changes it cannot know. It starts anyway (refusing would turn a
	// rollback into an outage), but never silently: silence is the actual defect.
	if embedded, applied, serr := postgres.SchemaSkew(ctx, pool); serr != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: could not determine schema skew: %v\n", serr)
	} else if applied > embedded {
		controlplane.SchemaSkew.Store(int64(applied - embedded))
		fmt.Fprintf(os.Stderr, "openshield-server: WARNING — the database has %d migration(s) this binary "+
			"does not know (applied=%d, embedded=%d). This is what a BINARY ROLLBACK looks like: the "+
			"schema is ahead of this process. Starting anyway. Note that migrations are FORWARD-ONLY — "+
			"rolling the BINARY back is supported, rolling the SCHEMA back is not.\n",
			applied-embedded, applied, embedded)
	}

	srv := controlplane.New(pool)

	// PLAT-5b: dynamic settings come from the DATABASE, and a watcher keeps them current in this process
	// so a saved change applies without a restart. Bootstrap fields still come from env/file — they have
	// to reach the process before the database does.
	settings := config.NewDBSource()
	cfg := serverConfig()
	cfg.DB = settings
	// SYNCHRONOUSLY first: everything below decides what to START from these values, so the first read
	// must not race the watcher's initial load.
	srv.LoadSettings(ctx, settings)
	go srv.WatchSettings(ctx, settings, envDuration("OPENSHIELD_CONFIG_POLL", 15*time.Second))
	// A dynamic field set in the environment does NOT take effect — and is never silent about it, because
	// the operator who set one believes it is doing something.
	if ignored := cfg.IgnoredOverrides(); len(ignored) > 0 {
		fmt.Fprintf(os.Stderr, "openshield-server: IGNORING environment values for dynamic settings %v — "+
			"these are stored in the database and changed there; set %s=<KEY> to override one deliberately "+
			"(it will then be reported as an override)\n", ignored, config.BreakGlassEnv)
	}

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
		// The SAME key signs RESPONSE INTENTS and FLEET CONTROLS, which is what this field has always
		// said it does ("signs risk and intent publications"). Until now only SetRiskSigner was called, so
		// PublishIntents and PublishFleetControl refused unconditionally — the IdP responder was listening
		// for a message nothing in the product could produce, and the emergency disable could not be sent
		// at all. A verifier with no possible signer is not a security control; it is an inert one.
		srv.SetIntentSigner(ed25519.PrivateKey(key))
		fmt.Fprintf(os.Stderr, "openshield-server: signed risk, intent and fleet-control publishing "+
			"enabled (SEC-1)\n")
	}

	// PLAT-2b/ADR-3: run the singleton work (telemetry consumer, peer analytics, maintenance loops)
	// under an active-passive leader lease — exactly one instance is leader; a standby waits and takes
	// over on leader failure. A single deployed instance becomes leader immediately (unchanged).
	leader := controlplane.NewLeader(pool)
	lerr := leader.Run(ctx, func(leaderCtx context.Context) {
		// SOAR-2: correlate on a CLOCK, not only when an operator asks. Before this, both materializers
		// were called from exactly one place — the GET /incidents handler — so an incident existed only if
		// a human happened to look, and SOAR-1's automatic page (D220) followed someone else's request.
		//
		// LEADER-ONLY (leaderCtx): every replica correlating would multiply materializations, and
		// materialization pages. The context is cancelled the moment leadership is lost, so a demoted
		// instance stops immediately rather than at the next tick.
		// PLAT-5b: the interval and both rules are read PER TICK from the live resolver, so a
		// configuration change applies to this running server without a restart. The loop always runs;
		// an interval of 0 means "not configured" and it simply does no work until one is set — so
		// turning correlation ON no longer requires a restart either.
		go srv.RunCorrelationLoop(leaderCtx,
			func() time.Duration { return cfg.Duration("OPENSHIELD_CORRELATE_INTERVAL") },
			func() (controlplane.CorrelationRule, controlplane.CrossDomainRule) {
				window := cfg.Duration("OPENSHIELD_CORRELATE_WINDOW")
				return controlplane.CorrelationRule{
						Window:    window,
						MinAlerts: cfg.Int("OPENSHIELD_CORRELATE_MIN_ALERTS"),
					}, controlplane.CrossDomainRule{
						Window:     window,
						MinDomains: cfg.Int("OPENSHIELD_CORRELATE_MIN_DOMAINS"),
					}
			}, nil)
		fmt.Fprintf(os.Stderr, "openshield-server: scheduled correlation loop ACTIVE (interval read live "+
			"from configuration; 0 = idle, no restart needed to change it)\n")

		// NIPS-6: sweep for beaconing on its OWN schedule. A 24h rhythm window on a 1h correlation tick
		// would either re-scan a day of telemetry every tick or measure rhythm over an hour, and neither
		// is the job. Interval and thresholds are read PER TICK, so retuning needs no restart.
		go srv.RunBeaconLoop(leaderCtx,
			func() time.Duration { return cfg.Duration("OPENSHIELD_BEACON_INTERVAL") },
			func() controlplane.BeaconRule {
				reg, _ := strconv.ParseFloat(cfg.String("OPENSHIELD_BEACON_MIN_REGULARITY"), 64)
				return controlplane.BeaconRule{
					Window: cfg.Duration("OPENSHIELD_BEACON_WINDOW"),
					Options: beacon.Options{
						MinContacts:   cfg.Int("OPENSHIELD_BEACON_MIN_CONTACTS"),
						MinRegularity: reg,
						MinInterval:   5 * time.Second,
					},
					Allowlist: splitCSV(cfg.String("OPENSHIELD_BEACON_ALLOWLIST")),
				}
			}, nil)
		fmt.Fprintf(os.Stderr, "openshield-server: beaconing sweep loop ACTIVE (interval read live; "+
			"0 = idle). Most beacons on a real network are legitimate — it raises MEDIUM alerts with "+
			"their evidence and enforces nothing.\n")

		// SOAR-3/D290: relabel timed-out four-eyes requests so the approval queue shows what can still
		// be actioned. LEADER-ONLY like the other maintenance loops.
		go srv.RunApprovalExpiryLoop(leaderCtx,
			func() time.Duration { return cfg.Duration("OPENSHIELD_APPROVAL_EXPIRY_INTERVAL") })

		// SOAR-4: run playbooks against matching incidents. LEADER-ONLY for the same reason correlation
		// is — every replica running playbooks would multiply notifications, cases and legal holds.
		//
		// Off unless a config file is named. A parse or validation failure is FATAL to the feature, not
		// to the process: a playbook naming an unknown step must never partially load (the registry is
		// closed at load, and a half-accepted playbook would make that meaningless), but orchestration
		// being misconfigured must not take detection down with it.
		if path := cfg.String("OPENSHIELD_PLAYBOOKS"); path != "" {
			pbs, err := loadPlaybookFile(path)
			switch {
			case err != nil:
				fmt.Fprintf(os.Stderr, "openshield-server: playbooks NOT loaded from %s: %v — "+
					"orchestration is OFF (detection and paging are unaffected)\n", path, err)
			case len(pbs) == 0:
				fmt.Fprintf(os.Stderr, "openshield-server: %s defines no playbooks — orchestration is OFF\n", path)
			default:
				pi := cfg.Duration("OPENSHIELD_PLAYBOOK_INTERVAL")
				go srv.RunPlaybookLoop(leaderCtx, pi, pbs, nil)
				fmt.Fprintf(os.Stderr, "openshield-server: playbook orchestration ACTIVE every %s — "+
					"%d playbook(s) from %s, Tier-1 only (no actuation) (leader only)\n", pi, len(pbs), path)
			}
		}

		// SOAR-5: keep the IOC store fresh without a human. LEADER-ONLY — every replica re-ingesting
		// the same snapshot would be redundant writes, not a correctness problem, but the leader lease
		// is where the singleton maintenance work belongs.
		//
		// A failure here is LOUD and never fatal: the previously ingested snapshot stays in place, which
		// is the right degradation — stale threat intel beats none, and beats a control plane that exits.
		if fp := cfg.String("OPENSHIELD_TI_FEED"); fp != "" {
			ti := cfg.Duration("OPENSHIELD_TI_FEED_INTERVAL")
			feedName := cfg.String("OPENSHIELD_TI_FEED_NAME")
			go retain.Loop(leaderCtx, ti, func(ctx context.Context) {
				pub, err := feedVerificationKey()
				if err != nil {
					fmt.Fprintf(os.Stderr, "openshield-server: TI feed key: %v\n", err)
					return
				}
				data, err := os.ReadFile(fp)
				if err != nil {
					fmt.Fprintf(os.Stderr, "openshield-server: reading TI feed %s: %v\n", fp, err)
					return
				}
				var sig []byte
				if len(pub) != 0 {
					if sig, err = os.ReadFile(fp + ".sig"); err != nil {
						fmt.Fprintf(os.Stderr, "openshield-server: reading TI feed signature: %v\n", err)
						return
					}
				}
				n, err := srv.IngestFeed(ctx, feedName, data, sig, pub,
					nips.Format(cfg.String("OPENSHIELD_TI_FEED_FORMAT")))
				if err != nil {
					fmt.Fprintf(os.Stderr, "openshield-server: TI feed REFUSED (previous snapshot kept): %v\n", err)
					return
				}
				fmt.Fprintf(os.Stderr, "openshield-server: TI feed %q refreshed: %d indicator(s)\n", feedName, n)
			})
		}

		// SOAR-8(b): the IdP responder. The Server owns the NATS connection, so the connector is
		// INSTALLED here and wired by Run.
		//
		// Off unless an endpoint is configured, and refused without a verification key: an intent that
		// does not verify against the control plane's key is not from the control plane, and an
		// unverifiable intent must never disable an account. The startup notice states plainly that these
		// actions are NOT undone by intent expiry — every other enactment in this platform is (D253/D254
		// both prove TTL restoration), so an operator's reasonable generalisation is wrong here.
		if ep := cfg.String("OPENSHIELD_IDP_ENDPOINT"); ep != "" {
			key, kerr := intentVerificationKey()
			switch {
			case kerr != nil:
				fmt.Fprintf(os.Stderr, "openshield-server: IdP responder NOT started: %v\n", kerr)
			case len(key) == 0:
				fmt.Fprintln(os.Stderr, "openshield-server: IdP responder NOT started — OPENSHIELD_INTENT_KEY "+
					"is unset, and an unverifiable intent must never disable an account")
			default:
				srv.SetIntentResponder(key, &runner.Connector{
					Name:     cfg.String("OPENSHIELD_IDP_NAME"),
					Endpoint: ep,
					Token:    os.Getenv("OPENSHIELD_IDP_TOKEN"),
					Actions: map[corev1.IntentVerb][]runner.Action{
						corev1.IntentVerb_INTENT_VERB_REVOKE_TRUST: {
							runner.ActionDisableUser, runner.ActionRevokeSessions,
						},
					},
					Timeout: cfg.Duration("OPENSHIELD_IDP_TIMEOUT"),
				})
			}
		}

		// SOAR-8(a): incident ⇄ ticket sync. LEADER-ONLY — several replicas syncing would open duplicate
		// tickets in someone else's system. POLLING, not a webhook: a webhook needs an authenticated
		// inbound route a third-party SaaS can reach, which is a new trust boundary; the cost here is that
		// sync-back lags by up to one interval.
		if ep := cfg.String("OPENSHIELD_ITSM_ENDPOINT"); ep != "" {
			statuses := strings.Split(cfg.String("OPENSHIELD_ITSM_CLOSED_STATUSES"), ",")
			itsm := &runner.ITSMConnector{
				Name:           cfg.String("OPENSHIELD_ITSM_NAME"),
				Endpoint:       ep,
				Token:          os.Getenv("OPENSHIELD_ITSM_TOKEN"),
				ClosedStatuses: statuses,
				MinSeverity:    cfg.String("OPENSHIELD_ITSM_MIN_SEVERITY"),
				Timeout:        cfg.Duration("OPENSHIELD_ITSM_TIMEOUT"),
			}
			si := cfg.Duration("OPENSHIELD_ITSM_INTERVAL")
			go srv.RunITSMLoop(leaderCtx, si, itsm, nil)
			fmt.Fprintf(os.Stderr, "openshield-server: ITSM sync ACTIVE every %s against %s — a ticket "+
				"reaching %v closes its incident; any OTHER status is ignored, never assumed closed "+
				"(leader only)\n", si, ep, statuses)
		}

		// Enforce the fleet-aggregate retention window (D81): purge received telemetry
		// and derived peer alerts older than the window, on a timer. The aggregate is a
		// derived view, so this is a hard delete (the evidentiary ledger tombstones
		// instead). Without it, personal-adjacent telemetry accrues forever (D20).
		retInterval := cfg.Duration("OPENSHIELD_RETENTION_INTERVAL")
		fleetRetention := cfg.Duration("OPENSHIELD_FLEET_RETENTION")
		fleetPolicy := fmt.Sprintf("OPENSHIELD_FLEET_RETENTION=%s", fleetRetention)
		go retain.Loop(leaderCtx, retInterval, func(ctx context.Context) {
			fleetCutoff := time.Now().Add(-fleetRetention)
			n, err := srv.PurgeOlderThan(ctx, fleetCutoff)
			if err != nil {
				fmt.Fprintf(os.Stderr, "openshield-server: retention purge failed: %v\n", err)
				return
			}
			fmt.Fprintf(os.Stderr, "openshield-server: retention purge removed %d fleet-aggregate rows\n", n)
			// SIEM-10: record the purge as a queryable compliance event (best-effort — the purge already
			// happened; a recording failure is counted, never undoes or blocks it).
			srv.RecordRetentionEvent(ctx, "fleet_telemetry", n, fleetCutoff, fleetPolicy)
			// SIEM-12/R34-13: prune the durable notify-dedupe ledger. An id only needs to outlive its
			// dedup window; a day-old cutoff keeps the table tiny while safely past the 10-min window.
			ddCutoff := time.Now().Add(-24 * time.Hour)
			if d, derr := srv.PruneNotifyDedupe(ctx, ddCutoff); derr != nil {
				fmt.Fprintf(os.Stderr, "openshield-server: notify-dedupe prune failed: %v\n", derr)
			} else {
				if d > 0 {
					fmt.Fprintf(os.Stderr, "openshield-server: pruned %d durable notify-dedupe ids\n", d)
				}
				srv.RecordRetentionEvent(ctx, "notify_dedupe", d, ddCutoff, "OPENSHIELD_NOTIFY_DEDUPE_RETENTION=24h")
			}
		})

		// SIEM-4: when OPENSHIELD_CEF_SYSLOG_LISTEN is set, receive CEF-over-syslog from the estate and
		// persist each parsed event as a searchable external log — OpenShield ingesting third-party
		// security logs, not only its own telemetry. Runs on the LEADER only (leaderCtx), so a standby
		// does not double-store; a listen error is logged, never fatal (an external feed is best-effort).
		if cefAddr := cfg.String("OPENSHIELD_CEF_SYSLOG_LISTEN"); cefAddr != "" {
			go func() {
				fmt.Fprintf(os.Stderr, "openshield-server: SIEM-4 CEF-over-syslog listener on %s\n", cefAddr)
				if err := srv.RunCEFSyslog(leaderCtx, cefAddr); err != nil && leaderCtx.Err() == nil {
					fmt.Fprintf(os.Stderr, "openshield-server: CEF-syslog listener stopped: %v\n", err)
				}
			}()
		}

		// SIEM-4: when OPENSHIELD_CLOUDTRAIL_DIR is set, ingest AWS CloudTrail deliveries dropped into
		// that directory (the S3-synced pattern) into the external-log store. Leader-only, so failover
		// does not double-ingest; a scan error is logged, never fatal.
		if ctDir := cfg.String("OPENSHIELD_CLOUDTRAIL_DIR"); ctDir != "" {
			go func() {
				fmt.Fprintf(os.Stderr, "openshield-server: SIEM-4 CloudTrail ingest watching %s\n", ctDir)
				if err := srv.RunCloudTrailIngest(leaderCtx, ctDir); err != nil && leaderCtx.Err() == nil {
					fmt.Fprintf(os.Stderr, "openshield-server: CloudTrail ingest stopped: %v\n", err)
				}
			}()
		}

		// SIEM-4: when OPENSHIELD_WEF_DIR is set, ingest Windows Event Forwarding XML files (a WEC export)
		// into the external-log store. Leader-only; a scan error is logged, never fatal.
		if wefDir := cfg.String("OPENSHIELD_WEF_DIR"); wefDir != "" {
			go func() {
				fmt.Fprintf(os.Stderr, "openshield-server: SIEM-4 WEF ingest watching %s\n", wefDir)
				if err := srv.RunWEFIngest(leaderCtx, wefDir); err != nil && leaderCtx.Err() == nil {
					fmt.Fprintf(os.Stderr, "openshield-server: WEF ingest stopped: %v\n", err)
				}
			}()
		}

		// Alert delivery (D83): when OPENSHIELD_ALERT_WEBHOOK is set, deliver peer-UEBA
		// alerts and overdue-agent alerts to a webhook so a human is TOLD, not left to
		// poll. Best-effort — a down sink never breaks ingest. Overdue notifications are
		// deduplicated (once per silence) and run on a timer.
		if hook := cfg.String("OPENSHIELD_ALERT_WEBHOOK"); hook != "" {
			// SIEM-8: wrap EACH webhook in bounded retry so a transient blip (a 5xx, a timeout during
			// a deploy) does not silently drop the page (a 4xx is not retried, see notify.Permanent),
			// then fan out to all of them via Multi — the retry is INNER so a retry re-attempts only the
			// failed sink, never re-paging a sink that already succeeded. OPENSHIELD_ALERT_WEBHOOK may be
			// a comma-separated list; OPENSHIELD_ALERT_WEBHOOK_SECRET (optional) HMAC-signs each body so a
			// receiver can verify the alert came from this control plane (unset = unsigned, unchanged).
			attempts := cfg.Int("OPENSHIELD_ALERT_RETRIES")
			secret := []byte(os.Getenv("OPENSHIELD_ALERT_WEBHOOK_SECRET"))
			//
			// SOAR-9: an entry may be `name=url` so a routing table can select it. A BARE URL still
			// works and is auto-named, so an existing deployment is untouched.
			var sinks []notify.Notifier
			named := map[string]notify.Notifier{}
			var order []string
			for i, u := range strings.Split(hook, ",") {
				u = strings.TrimSpace(u)
				if u == "" {
					continue
				}
				name := fmt.Sprintf("sink-%d", i)
				if eq := strings.Index(u, "="); eq > 0 && !strings.Contains(u[:eq], "/") {
					name, u = strings.TrimSpace(u[:eq]), strings.TrimSpace(u[eq+1:])
				}
				w := notify.NewWebhook(u)
				if len(secret) > 0 {
					w.Secret = secret
				}
				sink := notify.NewRetrying(w, attempts, 200*time.Millisecond)
				sinks = append(sinks, sink)
				named[name] = sink
				order = append(order, name)
			}
			// With no routing table the Router is not installed at all: delivery is exactly today's
			// fan-out-to-all. Nothing changes for a deployment until an operator writes a table.
			//
			// A table that fails to load leaves the fanout in place rather than taking notification down
			// — a misconfigured route must not become "nobody is paged".
			installed := false
			if rp := cfg.String("OPENSHIELD_ALERT_ROUTES"); rp != "" {
				if routes, err := loadRoutesFile(rp, order); err != nil {
					fmt.Fprintf(os.Stderr, "openshield-server: alert routes NOT loaded from %s: %v — "+
						"falling back to fan-out-to-ALL sinks (over-notifying, never silent)\n", rp, err)
				} else {
					srv.SetNotifier(&notify.Router{Sinks: named, Routes: routes})
					fmt.Fprintf(os.Stderr, "openshield-server: alert routing ACTIVE — %d rule(s) over %d "+
						"named sink(s); an unmatched notification goes to every sink and is counted\n",
						len(routes), len(named))
					installed = true
				}
			}
			if !installed {
				srv.SetNotifier(notify.NewMulti(sinks...))
			}
			overdueThreshold := cfg.Duration("OPENSHIELD_OVERDUE_THRESHOLD")
			overdueInterval := cfg.Duration("OPENSHIELD_OVERDUE_INTERVAL")
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
		if v := cfg.String("OPENSHIELD_PEER_UEBA_THRESHOLD"); v != "" {
			threshold, err := strconv.ParseFloat(v, 64)
			if err != nil {
				fatal("OPENSHIELD_PEER_UEBA_THRESHOLD=%q: %v", v, err)
			}
			cooldown := cfg.Duration("OPENSHIELD_PEER_UEBA_COOLDOWN")
			srv.EnablePeerUEBA(threshold, cooldown)
			peerUEBAEnabled = true
			fmt.Fprintf(os.Stderr, "openshield-server: peer-UEBA enabled (threshold %.2f, cooldown %s)\n", threshold, cooldown)

			// SIEM-5: persist the baseline periodically so a restart resumes it (EnablePeerUEBA
			// reloads it). Best-effort — a failed persist only shortens the next restart's warm
			// window, never breaks ingest. A final persist on shutdown runs after Run returns.
			persistInterval := cfg.Duration("OPENSHIELD_UEBA_PERSIST_INTERVAL")
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
	// R34-6: surface an UNEXPECTED election exit — Run returns nil-equivalent ctx.Err() on a clean
	// shutdown, so a non-ctx error here means the election machinery itself gave up (it no longer
	// does on transient DB errors) and must not be swallowed silently.
	if lerr != nil && ctx.Err() == nil {
		fatal("leader election: %v", lerr)
	}
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

// loadPlaybookFile reads and VALIDATES operator-supplied playbooks. Validation (including the closed
// step registry) happens here, at load — an unknown step name reaching execution would mean the registry
// was decorative.
func loadPlaybookFile(path string) ([]controlplane.Playbook, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return controlplane.LoadPlaybooks(f)
}

// ingestFeed is the operator-local threat-intel ingest (SOAR-5):
//
//	openshield-server ingest-feed <name> <feed-file> [<signature-file>]
//
// A SUBCOMMAND, not an HTTP route, for the D51 reason token issuance is not one: an endpoint that accepts
// indicator sets would let anything able to reach it decide what the platform calls a threat, which
// defeats the signature requirement standing next to it.
//
// The verification key comes from OPENSHIELD_TI_FEED_KEY (a raw ed25519 public key file). Without it the
// feed loads UNSIGNED — a visible configuration choice, printed as a warning, never a silent default.
func ingestFeed(dsn string, args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: openshield-server ingest-feed <name> <feed-file> [<signature-file>]")
		return 2
	}
	name, path := args[0], args[1]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: reading feed: %v\n", err)
		return 1
	}
	var sig []byte
	if len(args) > 2 {
		if sig, err = os.ReadFile(args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "openshield-server: reading signature: %v\n", err)
			return 1
		}
	}
	pub, err := feedVerificationKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: %v\n", err)
		return 1
	}
	if len(pub) == 0 {
		fmt.Fprintf(os.Stderr, "openshield-server: WARNING — OPENSHIELD_TI_FEED_KEY is unset, so %q is "+
			"ingested UNVERIFIED: whatever wrote that file decides what this platform calls a threat\n", path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: connecting: %v\n", err)
		return 1
	}
	defer pool.Close()
	srv := controlplane.New(pool)
	// The FORMAT is a dynamic setting, so it comes from the database here too. A subcommand reading it
	// from its own environment would parse a feed differently from the loop that re-ingests the same file
	// an hour later — the two paths must agree, and the console is what they agree with.
	fcfg := serverConfig()
	fdb := config.NewDBSource()
	fcfg.DB = fdb
	srv.LoadSettings(ctx, fdb)
	n, err := srv.IngestFeed(ctx, name, data, sig, pub, nips.Format(fcfg.String("OPENSHIELD_TI_FEED_FORMAT")))
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "openshield-server: ingested %d indicator(s) into feed %q (signed=%v)\n",
		n, name, len(pub) != 0)
	return 0
}

// feedVerificationKey loads the ed25519 public key feeds are verified against, if configured.
func feedVerificationKey() (ed25519.PublicKey, error) {
	kp := os.Getenv("OPENSHIELD_TI_FEED_KEY")
	if kp == "" {
		return nil, nil
	}
	key, err := os.ReadFile(kp)
	if err != nil {
		return nil, fmt.Errorf("reading TI feed key: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("TI feed key is %d bytes, want %d (raw ed25519 public key)", len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

// loadRoutesFile reads and VALIDATES an operator routing table against the configured sink names
// (SOAR-9). Validation is at load because a routing mistake found at delivery time is found by an alert
// not arriving.
func loadRoutesFile(path string, sinkNames []string) ([]notify.Route, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return notify.LoadRoutes(f, sinkNames)
}

// intentVerificationKey loads the control-plane public key an intent must verify against before the
// runner will act on it. Unset means the responder does not start: an unverifiable intent must never
// disable an account.
func intentVerificationKey() (ed25519.PublicKey, error) {
	kp := os.Getenv("OPENSHIELD_INTENT_KEY")
	if kp == "" {
		return nil, nil
	}
	key, err := os.ReadFile(kp)
	if err != nil {
		return nil, fmt.Errorf("reading intent verification key: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("intent key is %d bytes, want %d (raw ed25519 public key)", len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

// serverConfig builds the resolver over the DECLARED field set, env taking precedence over an optional
// file (OPENSHIELD_CONFIG_FILE) over the declared default. Env stays on top so an operator can override a
// stored value on a single host during an incident, without a database — the property that matters when a
// UI is eventually the usual way these are set.
func serverConfig() *config.Resolver {
	sources := []config.Source{config.EnvSource{}}
	if path := os.Getenv("OPENSHIELD_CONFIG_FILE"); path != "" {
		fs, err := config.LoadFile(path)
		if err != nil {
			fatal("reading %s: %v", path, err)
		}
		sources = append(sources, fs)
	}
	return config.New(config.ServerFields, sources...)
}

// showConfig prints the schema and what this process would actually honour, with SECRETS REDACTED — the
// operator-visible half of PLAT-5 now, and the same data a UI will render later.
func showConfig() int {
	r := serverConfig()
	fmt.Fprintln(os.Stdout, "# effective configuration (secrets shown as set/unset, never by value)")
	r.WriteEffective(os.Stdout)
	if err := r.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "\n%v\n", err)
		return 1
	}
	return 0
}

// splitCSV splits a comma-separated setting, dropping blanks. Trivial, but written once: three call sites
// each trimming differently is how one of them ends up matching " host" and never firing.
func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
