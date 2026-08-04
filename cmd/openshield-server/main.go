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
	"crypto/tls"
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
	identitypkg "github.com/lucianoengel/openshield/internal/gateway/identity"
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
			os.Exit(showConfig(dsn))
		case "operator-role":
			os.Exit(operatorRole(dsn, os.Args[2:]))
		case "machine-credential":
			os.Exit(machineCredential(dsn, os.Args[2:]))
		}
	}
	// ZT-7: operator SSO. Off unless an issuer is configured — enabling an IdP must not happen by accident.
	// The token AUTHENTICATES; the role still comes from the operator record, so a demotion applies to a
	// token already issued (see internal/controlplane/operator_roles.go).
	operatorSSOEnabled := false
	setUpOperatorSSO := func(srv *controlplane.Server, ctx context.Context) {
		issuer := os.Getenv("OPENSHIELD_OPERATOR_OIDC_ISSUER")
		audience := os.Getenv("OPENSHIELD_OPERATOR_OIDC_AUDIENCE")
		jwksURL := os.Getenv("OPENSHIELD_OPERATOR_OIDC_JWKS_URL")
		if issuer == "" {
			return
		}
		keysDir := os.Getenv("OPENSHIELD_OPERATOR_OIDC_KEYS_DIR")
		if audience == "" || (jwksURL == "" && keysDir == "") {
			// A half-configured IdP must not silently mean "certificates only": an operator team that
			// believes SSO is on would find out from a support ticket.
			fatal("operator SSO: OPENSHIELD_OPERATOR_OIDC_ISSUER is set but AUDIENCE, or both JWKS_URL and " +
				"KEYS_DIR, are not")
		}
		if jwksURL != "" && keysDir != "" {
			// Two key sources is ambiguous about which one is authoritative, and a deployment that thinks
			// it rotated keys in the one that is being ignored has a silent trust problem.
			fatal("operator SSO: set OPENSHIELD_OPERATOR_OIDC_JWKS_URL or _KEYS_DIR, not both")
		}
		// NO ROLE CLAIM, by construction: the operator constructors do not take one, because reading a role
		// out of the token is the defect ZT-7 removed from certificates.
		var v *identitypkg.OIDCVerifier
		var verr error
		if jwksURL != "" {
			ref, rerr := identitypkg.NewJWKSRefresher(jwksURL, envDuration("OPENSHIELD_OPERATOR_OIDC_JWKS_INTERVAL", 5*time.Minute))
			if rerr != nil {
				fatal("operator SSO: %v", rerr)
			}
			ref.Start(ctx)
			v, verr = identitypkg.NewOperatorVerifierWithSource(issuer, audience, ref.KeyFor)
		} else {
			keys, kerr := identitypkg.LoadOIDCKeys(keysDir)
			if kerr != nil {
				fatal("operator SSO: %v", kerr)
			}
			v, verr = identitypkg.NewOperatorVerifier(issuer, audience, keys)
		}
		if verr != nil {
			fatal("operator SSO: %v", verr)
		}
		// SENDER-CONSTRAINING IS ALWAYS AVAILABLE, so a token the issuer bound is always checked. Whether an
		// UNBOUND token is refused is the separate hardening switch OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP —
		// enabling proof validation costs nothing and refusing plain bearers would lock out a deployment
		// whose issuer does not bind yet.
		v.EnableDPoP(envInt("OPENSHIELD_OPERATOR_OIDC_DPOP_REPLAY_CACHE", 4096))
		srv.SetOperatorOIDC(v)
		operatorSSOEnabled = true
		fmt.Fprintf(os.Stderr, "openshield-server: operator SSO ACTIVE (issuer %s). Tokens AUTHENTICATE; "+
			"authorization still comes from `operator-role set`, so an SSO operator with no record has no "+
			"access whatever their token claims.\n", issuer)
	}
	// SEC-D: say what this deployment's two-person control is actually worth, unprompted, every boot.
	//
	// Four-eyes compares an identity string, and two shipped defaults decide what an identity string is
	// worth — whether an identity with no server-side row falls back to its certificate, and whether an
	// unbound operator token is accepted. Both defaults are defensible; what was not is that four-eyes
	// said nothing about them, so an approval recorded on a deployment where two credentials are two
	// "operators" produced an audit trail attesting to a control that did not exist.
	//
	// Printed at every boot rather than only when weak: an operator who has hardened a deployment needs
	// to be able to confirm it, and a message that appears only on failure is one nobody can use to
	// verify success.
	fmt.Fprintf(os.Stderr, "openshield-server: %s\n",
		controlplane.FourEyesStartupNotice(controlplane.AssessFourEyes()))

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
	setUpOperatorSSO(srv, ctx)
	// CONSOLE-1: a machine credential that exists and cannot reach the listener is a silent gap (D31).
	warnAboutUnreachableMachineCredentials(ctx, srv, operatorSSOEnabled)
	go srv.WatchSettings(ctx, settings, envDuration("OPENSHIELD_CONFIG_POLL", 15*time.Second))
	// D292: the configuration surface reports and validates against THIS process's resolver, so what an
	// operator reads is what this binary is honouring — not a fresh one built inside a handler, which
	// would describe a process that does not exist.
	srv.SetConfigResolver(cfg)
	// A dynamic field set in the environment does NOT take effect — and is never silent about it, because
	// the operator who set one believes it is doing something.
	// The BREAK-GLASS overrides in force. Announced loudly, because this host is deliberately not running
	// what the console says, and the person who needs to know that is whoever reads the logs during the
	// next incident — not whoever thinks to query /config (D317).
	if active := cfg.ActiveOverrides(); len(active) > 0 {
		fmt.Fprintf(os.Stderr, "openshield-server: BREAK-GLASS OVERRIDES ACTIVE for %v — these are taken "+
			"from the ENVIRONMENT and this host is NOT running the stored value the console shows. "+
			"Remove them from %s once the incident is over.\n", active, config.BreakGlassEnv)
	}
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
				recur := cfg.Duration("OPENSHIELD_INCIDENT_RECURRENCE_WINDOW")
				return controlplane.CorrelationRule{
						Window:           window,
						MinAlerts:        cfg.Int("OPENSHIELD_CORRELATE_MIN_ALERTS"),
						RecurrenceWindow: recur,
					}, controlplane.CrossDomainRule{
						Window:           window,
						MinDomains:       cfg.Int("OPENSHIELD_CORRELATE_MIN_DOMAINS"),
						RecurrenceWindow: recur,
					}
			},
			// XDR-4c: the NARRATIVE rules, read per tick from the hunt file. Before this, XDR-4's
			// ordered-sequence rule was reachable only from the GET /incidents query parser: the
			// platform could answer "did this chain happen?" for an operator who already suspected it,
			// and could never tell anyone. A hunt file that fails to parse leaves hunts OFF and counts
			// it — substituting a default would raise incidents against a narrative nobody wrote.
			func() []controlplane.CrossDomainRule {
				p := cfg.String("OPENSHIELD_CORRELATION_HUNTS")
				if p == "" {
					return nil // not configured: the breadth rule alone, exactly as before
				}
				h, err := loadHuntsFile(p)
				if err != nil {
					controlplane.CorrelationFailures.Add(1)
					return nil
				}
				return h.Rules(cfg.Duration("OPENSHIELD_CORRELATE_WINDOW"),
					cfg.Int("OPENSHIELD_CORRELATE_MIN_DOMAINS"),
					cfg.Duration("OPENSHIELD_INCIDENT_RECURRENCE_WINDOW"))
			}, nil)
		fmt.Fprintf(os.Stderr, "openshield-server: scheduled correlation loop ACTIVE (interval read live "+
			"from configuration; 0 = idle, no restart needed to change it)\n")
		// Say at startup whether the narrative rules are on, and NAME a broken hunt file. A hunt that
		// silently fails to load matches nothing, and nothing-matched is indistinguishable from
		// nothing-happened — which is the exact failure the loader's validation exists to refuse.
		if p := cfg.String("OPENSHIELD_CORRELATION_HUNTS"); p == "" {
			fmt.Fprintf(os.Stderr, "openshield-server: correlation hunts IDLE — set "+
				"OPENSHIELD_CORRELATION_HUNTS to a hunt file to raise incidents on ATT&CK/domain "+
				"sequences automatically (no restart needed)\n")
		} else if h, err := loadHuntsFile(p); err != nil {
			fmt.Fprintf(os.Stderr, "openshield-server: correlation hunts NOT loaded from %s: %v — "+
				"narrative sequences will NOT raise incidents\n", p, err)
		} else {
			fmt.Fprintf(os.Stderr, "openshield-server: correlation hunts ACTIVE from %s (%d hunt(s), "+
				"run on every correlation tick alongside the breadth rule)\n", p, len(h.Hunts))
		}

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

		// SOAR-7/D291: the intent BLAST-RADIUS ceiling. Never set before, so never enforced — the
		// check existed and the value it compared against was always zero, which the code reads as "no
		// ceiling". Applied per tick from the live resolver so it can be tightened without a restart,
		// which is the direction an operator is likely to want it in a hurry.
		go retain.Loop(ctx, 15*time.Second, func(context.Context) {
			srv.SetIntentBlastRadius(cfg.Int("OPENSHIELD_INTENT_BLAST_RADIUS"))
		})
		srv.SetIntentBlastRadius(cfg.Int("OPENSHIELD_INTENT_BLAST_RADIUS"))

		// SOAR-3/D290: relabel timed-out four-eyes requests so the approval queue shows what can still
		// be actioned. LEADER-ONLY like the other maintenance loops.
		go srv.RunApprovalExpiryLoop(leaderCtx,
			func() time.Duration { return cfg.Duration("OPENSHIELD_APPROVAL_EXPIRY_INTERVAL") })

		// SOAR-4: run playbooks against matching incidents. LEADER-ONLY for the same reason correlation
		// is — every replica running playbooks would multiply notifications, cases and legal holds.
		//
		// The file is re-read PER TICK (D292). It used to be loaded once at leader startup, which made
		// OPENSHIELD_PLAYBOOKS a dynamic setting that silently required a restart — an operator enabling
		// orchestration in the console would have watched their saved change do nothing.
		//
		// A parse or validation failure is FATAL TO THE FEATURE, not to the process: a playbook naming an
		// unknown step must never partially load, but orchestration being misconfigured must not take
		// detection down with it. The failure is announced ONCE PER DISTINCT ERROR rather than every
		// tick, because a loop that logs the same failure every second is one whose output gets muted.
		var lastPlaybookNote string
		notePlaybooks := func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			if msg != lastPlaybookNote {
				lastPlaybookNote = msg
				fmt.Fprint(os.Stderr, msg)
			}
		}
		go srv.RunPlaybookLoop(leaderCtx,
			func() time.Duration { return cfg.Duration("OPENSHIELD_PLAYBOOK_INTERVAL") },
			func() []controlplane.Playbook {
				path := cfg.String("OPENSHIELD_PLAYBOOKS")
				if path == "" {
					return nil
				}
				pbs, err := loadPlaybookFile(path)
				switch {
				case err != nil:
					notePlaybooks("openshield-server: playbooks NOT loaded from %s: %v — orchestration is "+
						"OFF (detection and paging are unaffected)\n", path, err)
					return nil
				case len(pbs) == 0:
					notePlaybooks("openshield-server: %s defines no playbooks — orchestration is OFF\n", path)
					return nil
				}
				notePlaybooks("openshield-server: playbook orchestration ACTIVE — %d playbook(s) from %s, "+
					"Tier-1 only (no actuation) (leader only)\n", len(pbs), path)
				return pbs
			}, nil)

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
			// dedup window, so the retention is several windows rather than one.
			//
			// THE CUTOFF COMES FROM THE SETTING, and the recorded policy is built from the value actually
			// used (D333). It used to be a hardcoded 24h while the compliance event recorded the literal
			// string "OPENSHIELD_NOTIFY_DEDUPE_RETENTION=24h" — so an operator who set 7d had their value
			// ignored AND got a retention record naming their knob while asserting someone else's value.
			// A compliance record citing a setting nobody read is worse than one that omits it: it is
			// evidence of a policy that was never applied.
			ddRetention := cfg.Duration("OPENSHIELD_NOTIFY_DEDUPE_RETENTION")
			ddCutoff := time.Now().Add(-ddRetention)
			ddPolicy := fmt.Sprintf("OPENSHIELD_NOTIFY_DEDUPE_RETENTION=%s", ddRetention)
			if d, derr := srv.PruneNotifyDedupe(ctx, ddCutoff); derr != nil {
				fmt.Fprintf(os.Stderr, "openshield-server: notify-dedupe prune failed: %v\n", derr)
			} else {
				if d > 0 {
					fmt.Fprintf(os.Stderr, "openshield-server: pruned %d durable notify-dedupe ids\n", d)
				}
				srv.RecordRetentionEvent(ctx, "notify_dedupe", d, ddCutoff, ddPolicy)
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

		// SIEM-4 reliable ingest (D337): the same CEF/RFC-5424 sink over a STREAM transport, because the
		// datagram listener cannot lose events VISIBLY — a datagram the kernel discards for want of
		// buffer never reaches this process, so no counter here can see it. TCP adds delivery and
		// backpressure; TLS adds an authenticated sender, without which anything that can reach the port
		// can inject events into a store operators are invited to treat as evidence.
		for _, sl := range []struct {
			addr string
			tls  bool
			what string
		}{
			{cfg.String("OPENSHIELD_SYSLOG_TCP_LISTEN"), false,
				"delivery + backpressure; the SENDER IS NOT AUTHENTICATED"},
			{cfg.String("OPENSHIELD_SYSLOG_TLS_LISTEN"), true,
				"delivery + backpressure + a sender authenticated by client certificate"},
		} {
			if sl.addr == "" {
				continue
			}
			var tlsConf *tls.Config
			if sl.tls {
				tc, terr := tlsconf.LoadFromEnv()
				if terr != nil {
					fatal("syslog TLS ingest: %v", terr)
				}
				if tc == nil {
					// FAIL, do not fall back to plaintext. An operator who configured a TLS ingest port
					// and got an unauthenticated one has the opposite of what they asked for, silently.
					fatal("OPENSHIELD_SYSLOG_TLS_LISTEN is set but no TLS material is configured (%s/%s/%s) "+
						"— refusing to serve evidentiary ingest without an authenticated sender",
						tlsconf.EnvCA, tlsconf.EnvCert, tlsconf.EnvKey)
				}
				tlsConf = tc.ServerConfig()
			}
			addr, what := sl.addr, sl.what
			fmt.Fprintf(os.Stderr, "openshield-server: SIEM-4 syslog STREAM ingest on %s — %s\n", addr, what)
			go func() {
				if err := srv.RunCEFSyslogStream(leaderCtx, addr, tlsConf); err != nil && leaderCtx.Err() == nil {
					fmt.Fprintf(os.Stderr, "openshield-server: syslog stream listener on %s stopped: %v\n", addr, err)
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

		// SIEM-15: generic newline-delimited JSON ingest. Leader-only, same as the other file pollers.
		if jsonDir := cfg.String("OPENSHIELD_JSONLOG_DIR"); jsonDir != "" {
			vendor := cfg.String("OPENSHIELD_JSONLOG_VENDOR")
			go func() {
				fmt.Fprintf(os.Stderr, "openshield-server: SIEM-15 JSON-lines ingest watching %s "+
					"(vendor %q)\n", jsonDir, vendor)
				if err := srv.RunJSONLogIngest(leaderCtx, jsonDir, vendor); err != nil && leaderCtx.Err() == nil {
					fmt.Fprintf(os.Stderr, "openshield-server: JSON-lines ingest stopped: %v\n", err)
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
			// SOAR-9b: escalate incidents nobody acknowledges. Read PER TICK so a ladder change applies
			// without a restart, and leader-only so replicas do not multiply the page.
			//
			// A ladder that fails to load leaves escalation OFF and says so, rather than substituting a
			// default: guessing at deadlines an operator did not write would page people on a schedule
			// nobody agreed to, and the honest failure of a broken ladder is that it does not run.
			sinkOrder := order
			if p := cfg.String("OPENSHIELD_ESCALATION_LADDER"); p == "" {
				fmt.Fprintf(os.Stderr, "openshield-server: incident escalation IDLE — set "+
					"OPENSHIELD_ESCALATION_LADDER to a ladder file to turn it on (no restart needed)\n")
			} else if _, err := loadLadderFile(p, sinkOrder); err != nil {
				fmt.Fprintf(os.Stderr, "openshield-server: escalation ladder NOT loaded from %s: %v — "+
					"unacknowledged incidents will NOT be escalated\n", p, err)
			} else {
				fmt.Fprintf(os.Stderr, "openshield-server: incident escalation ACTIVE from %s "+
					"(acknowledging an incident stops its ladder)\n", p)
			}
			// The loop ALWAYS runs and reads path + ladder per tick, so both enabling escalation and
			// editing the ladder apply to a running server. Gating the goroutine on the value read at
			// start would make "dynamic" mean "dynamic once you restart", which is the shape PLAT-5b
			// exists to refuse.
			go srv.RunEscalationLoop(leaderCtx,
				func() time.Duration { return cfg.Duration("OPENSHIELD_ESCALATION_INTERVAL") },
				func() controlplane.Ladder {
					p := cfg.String("OPENSHIELD_ESCALATION_LADDER")
					if p == "" {
						return controlplane.Ladder{} // not configured: no rungs, nothing fires
					}
					l, err := loadLadderFile(p, sinkOrder)
					if err != nil {
						// A file edited into an invalid state must not silently disable escalation:
						// count it where the operator already looks.
						controlplane.EscalationFailures.Add(1)
						return controlplane.Ladder{}
					}
					return l
				}, nil)

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
					// WHEN OPERATOR SSO IS ON, a client certificate becomes OPTIONAL at the handshake.
					// Without this the feature is unreachable: an SSO operator has no certificate, so the
					// mutual-TLS listener refuses them with `tls: certificate required` before the bearer
					// token is ever read. A presented certificate is still verified against the CA, so
					// certificate authentication is unchanged and an unknown one is still refused here —
					// only ABSENCE stops being fatal, becoming a 401 one layer up.
					//
					// MACHINE CREDENTIALS NEED THE SAME RELAXATION, and gating it on SSO alone would have
					// shipped them unreachable in exactly the way D375 describes: an automation presenting
					// `osm_…` has no certificate either, so a deployment with no identity provider would
					// refuse a perfectly valid credential at the handshake, before the token was read.
					cfg := tlsConf.ServerConfig()
					if operatorSSOEnabled || machineTokensEnabled() {
						cfg = tlsConf.ServerConfigOptionalClientCert()
					}
					serveErr = srv.ServeHTTPTLS(leaderCtx, addr, cfg)
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

// operatorRole grants, changes or revokes an operator's authorization (ZT-7).
//
// AN OPERATOR-LOCAL COMMAND, not a network route, for the same reason issuance and agent revocation are
// (D51): the ability to hand out admin must not itself be reachable over the network the admin console
// uses. Whoever runs this already has database credentials and shell on the control plane.
func operatorRole(dsn string, args []string) int {
	usage := "usage: openshield-server operator-role set <identity> <grant>\n" +
		"       openshield-server operator-role revoke <identity>\n" +
		"       openshield-server operator-role list\n\n" +
		"<grant> is an operational TIER, the PRIVACY authority, or both (CONSOLE-1):\n" +
		"  analyst | responder | admin   the tiers, ordered; a higher one satisfies a lower\n" +
		"  privacy-officer               DSAR export, legal-hold release, and the record of who viewed\n" +
		"                                what. NOT a tier: no tier grants it and it grants no tier.\n" +
		"  admin,privacy-officer         both — what `admin` alone meant before this split, and what\n" +
		"                                every existing admin was migrated to so nothing broke\n\n" +
		"The grant is REPLACED, not merged, so `set <identity> admin` is how the privacy authority comes\n" +
		"back off an administrator who was migrated with both.\n\n" +
		"<identity> is a NAMESPACED PRINCIPAL naming the credential that will present it (CONSOLE-1):\n" +
		"  cert:<CommonName>          a CA-issued operator client certificate\n" +
		"  oidc:<issuer>#<subject>    a verified operator bearer token\n" +
		"  svc:<name>                 a machine principal; can never satisfy four-eyes\n\n" +
		"A bare name is refused. The issuer is part of an SSO identity because a subject is unique only\n" +
		"within one issuer — and without it, a provider that calls someone \"alice\" would inherit the\n" +
		"grant made to the certificate whose CommonName is alice.\n\n" +
		"Takes effect on the operator's NEXT REQUEST — the role is resolved server-side per request, not\n" +
		"baked into their certificate."
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "operator-role:", err)
		return 1
	}
	defer pool.Close()
	srv := controlplane.New(pool)
	// WHO made the change, recorded on the row. An authorization change is itself a security event, and one
	// that cannot be attributed is not evidence.
	by := env("USER", "unknown") + "@" + hostname()

	switch args[0] {
	case "set":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		if err := srv.SetOperatorRole(ctx, args[1], args[2], by); err != nil {
			fmt.Fprintln(os.Stderr, "operator-role set:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "%s is now %s (effective on their next request)\n", args[1], args[2])
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		if err := srv.RevokeOperator(ctx, args[1], by); err != nil {
			fmt.Fprintln(os.Stderr, "operator-role revoke:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "%s is REVOKED (effective on their next request). Their certificate still\n"+
			"authenticates them; it no longer authorizes anything.\n", args[1])
	case "list":
		rows, err := srv.ListOperatorRoles(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "operator-role list:", err)
			return 1
		}
		if len(rows) == 0 {
			fmt.Fprintln(os.Stderr, "no operator rows — every operator is running on the role embedded in "+
				"its certificate, which cannot be changed without reissuing it")
		}
		for _, r := range rows {
			state := r.Role
			if r.Revoked {
				state = "REVOKED"
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", r.Identity, state, r.UpdatedAt.UTC().Format(time.RFC3339), r.UpdatedBy)
		}
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	return 0
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
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

// loadLadderFile reads and VALIDATES an escalation ladder against the configured sink names (SOAR-9b).
// Same discipline as the routing table, for the same reason: an escalation mistake found at firing time
// is found by a page that did not arrive.
// loadHuntsFile reads and validates the XDR-4c hunt file. Same shape as loadLadderFile, and the same
// reasoning: the file is re-read per tick so an edit applies without a restart, and validation happens
// at load because a mistake discovered at match time is discovered as an absence of incidents.
func loadHuntsFile(path string) (controlplane.Hunts, error) {
	f, err := os.Open(path)
	if err != nil {
		return controlplane.Hunts{}, err
	}
	defer f.Close()
	return controlplane.LoadHunts(f)
}

func loadLadderFile(path string, sinkNames []string) (controlplane.Ladder, error) {
	f, err := os.Open(path)
	if err != nil {
		return controlplane.Ladder{}, err
	}
	defer f.Close()
	return controlplane.LoadLadder(f, sinkNames)
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
// showConfig prints what this deployment is ACTUALLY running with.
//
// It reads the STORED settings, and that was missing (D303). Without it the command built a resolver
// with no database source, so every dynamic setting printed as `[default]` no matter what an operator
// had saved — in the one command whose entire purpose is answering "what is this deployment running
// with". An operator debugging a setting that will not apply runs this, sees the default, and concludes
// their save failed; an operator checking a deployment sees defaults and believes it is at them.
//
// D285's test for this command asserted bootstrap values and secret redaction, which is why the gap
// survived: both of those are correct, and neither touches the database.
//
// A DATABASE THAT CANNOT BE READ IS REPORTED, NOT PAPERED OVER. Falling back to defaults silently would
// reproduce the exact defect — the output would be indistinguishable from a deployment genuinely at its
// defaults.
func showConfig(dsn string) int {
	r := serverConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stored := "stored settings included"
	if pool, err := pgxpool.New(ctx, dsn); err != nil {
		stored = "WARNING: could not connect to the database — DYNAMIC VALUES BELOW ARE DEFAULTS, NOT WHAT " +
			"THIS DEPLOYMENT RUNS WITH: " + err.Error()
	} else {
		defer pool.Close()
		db := config.NewDBSource()
		controlplane.New(pool).LoadSettings(ctx, db)
		r.DB = db
	}
	fmt.Fprintln(os.Stdout, "# effective configuration (secrets shown as set/unset, never by value)")
	fmt.Fprintln(os.Stdout, "# "+stored)
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

// machineCredential is the `svc:<name>` lifecycle (CONSOLE-1): issue, rotate, revoke, list.
//
// AN OPERATOR-LOCAL COMMAND for the same reason `operator-role` is (D51): minting a credential that can
// call the operator API must not itself be reachable over the operator API.
//
// The subcommand exists because the machine principal had a namespace and no credential — nothing could
// present a `svc:` identity, so every automation ran on a person's certificate or a person's SSO token,
// which is exactly the input the four-eyes account comparison exists to reject.
func machineCredential(dsn string, args []string) int {
	usage := "usage: openshield-server machine-credential issue <name> --ttl <duration>\n" +
		"       openshield-server machine-credential rotate <name> --ttl <duration>\n" +
		"       openshield-server machine-credential revoke <name>\n" +
		"       openshield-server machine-credential list\n\n" +
		"Mints the credential for the machine principal `svc:<name>`. THE TOKEN IS PRINTED ONCE and only\n" +
		"its hash is stored, so a lost secret is rotated rather than recovered.\n\n" +
		"--ttl is REQUIRED and capped at 90 days. There is no non-expiring machine credential: the one\n" +
		"nobody rotates is the one that never had to be.\n\n" +
		"ISSUING GRANTS NOTHING. Authorize it like any operator:\n" +
		"  openshield-server operator-role set svc:<name> analyst\n" +
		"A machine principal may REQUEST an approval and may never grant one (SOAR-4, D469)."
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	// ttlArg reads `--ttl <duration>` from the remaining arguments. Absent is an ERROR rather than a
	// default, because a default life is a life nobody chose.
	ttlArg := func(rest []string) (time.Duration, bool) {
		for i := 0; i < len(rest)-1; i++ {
			if rest[i] == "--ttl" {
				d, err := time.ParseDuration(rest[i+1])
				if err != nil {
					fmt.Fprintln(os.Stderr, "machine-credential: --ttl:", err)
					return 0, false
				}
				return d, true
			}
		}
		fmt.Fprintln(os.Stderr, "machine-credential: --ttl is required (for example --ttl 720h)")
		return 0, false
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "machine-credential:", err)
		return 1
	}
	defer pool.Close()
	srv := controlplane.New(pool)
	by := env("USER", "unknown") + "@" + hostname()

	// printed reports a freshly minted secret. To STDOUT so it can be piped into a secret store, while
	// every explanation goes to stderr — a token with prose around it is a token somebody pastes wrong.
	printed := func(name, secret string) {
		fmt.Println(secret)
		fmt.Fprintf(os.Stderr, "svc:%s — this is the only time the token is shown. It grants NOTHING "+
			"until you run `openshield-server operator-role set svc:%s <role>`.\n", name, name)
	}

	switch args[0] {
	case "issue", "rotate":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		ttl, ok := ttlArg(args[2:])
		if !ok {
			return 2
		}
		var secret error
		var tok string
		if args[0] == "issue" {
			tok, secret = srv.IssueMachineCredential(ctx, args[1], ttl, by)
		} else {
			tok, secret = srv.RotateMachineCredential(ctx, args[1], ttl, by)
		}
		if secret != nil {
			fmt.Fprintf(os.Stderr, "machine-credential %s: %v\n", args[0], secret)
			return 1
		}
		printed(args[1], tok)
		if args[0] == "rotate" {
			fmt.Fprintln(os.Stderr, "The previous secret stopped working immediately — there is no "+
				"overlap window, so update the automation in this same change.")
		}
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		if err := srv.RevokeMachineCredential(ctx, args[1], by); err != nil {
			fmt.Fprintln(os.Stderr, "machine-credential revoke:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "svc:%s is REVOKED — it authenticates nothing as of now. Its operator-role "+
			"grant is untouched; revoke that too if the identity is going away.\n", args[1])
	case "list":
		rows, err := srv.ListMachineCredentials(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "machine-credential list:", err)
			return 1
		}
		if len(rows) == 0 {
			fmt.Fprintln(os.Stderr, "no machine credentials — any automation calling the operator API is "+
				"doing so as a PERSON, which is what four-eyes cannot see through")
		}
		now := time.Now()
		for _, r := range rows {
			state := "active"
			switch {
			case r.Revoked:
				state = "REVOKED"
			case r.Expired(now):
				state = "EXPIRED"
			}
			used := "never"
			if r.LastUsedAt.After(time.Unix(0, 0)) {
				used = r.LastUsedAt.UTC().Format(time.RFC3339)
			}
			fmt.Printf("%s\t%s\texpires=%s\tlast_used=%s\trotations=%d\t%s\n", r.Principal, state,
				r.ExpiresAt.UTC().Format(time.RFC3339), used, r.Rotations, r.IssuedBy)
		}
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	return 0
}

// machineTokensEnabled reports whether this deployment accepts machine bearer credentials at the
// handshake (CONSOLE-1).
//
// OFF BY DEFAULT, and the same shape as operator SSO for the same reason: accepting a handshake with no
// client certificate is a posture change, and a posture change must be a decision rather than a side
// effect of somebody running an unrelated command. A deployment that never issues a machine credential
// keeps the mutual-TLS refusal it has always had.
//
// The cost of an off-by-default switch is a silent failure — issue a credential, watch it not work, no
// clue why — so warnAboutUnreachableMachineCredentials exists to make that state loud rather than
// leaving it to be discovered (D31).
func machineTokensEnabled() bool {
	return strings.TrimSpace(os.Getenv("OPENSHIELD_OPERATOR_MACHINE_TOKENS")) == "1"
}

// warnAboutUnreachableMachineCredentials reports, at boot, credentials that exist and cannot be used.
//
// The pairing is what makes this checkable: a credential in the table plus a listener that refuses a
// certificate-less handshake means an automation is getting `tls: certificate required` and its owner is
// reading it as a networking problem. D31 — a gap must never be silent.
func warnAboutUnreachableMachineCredentials(ctx context.Context, srv *controlplane.Server, ssoOn bool) {
	if ssoOn || machineTokensEnabled() {
		return
	}
	rows, err := srv.ListMachineCredentials(ctx)
	if err != nil {
		return // a boot-time advisory must never be the reason a server fails to start
	}
	var live int
	now := time.Now()
	for _, r := range rows {
		if !r.Revoked && !r.Expired(now) {
			live++
		}
	}
	if live == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "openshield-server: %d active machine credential(s) exist and CANNOT BE USED: "+
		"this listener requires a client certificate at the handshake, so an automation presenting a "+
		"machine token is refused with `tls: certificate required` before the token is read. Set "+
		"OPENSHIELD_OPERATOR_MACHINE_TOKENS=1 to accept them (a presented certificate is still verified; "+
		"only its ABSENCE stops being fatal), or revoke them with "+
		"`openshield-server machine-credential revoke <name>`.\n", live)
}
