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
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/lucianoengel/openshield/internal/agent/openipc"
	"github.com/lucianoengel/openshield/internal/agent/prefilter"
	"github.com/lucianoengel/openshield/internal/config"
	"github.com/lucianoengel/openshield/internal/connectors/dns"
	"github.com/lucianoengel/openshield/internal/connectors/execaudit"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	enrollpkg "github.com/lucianoengel/openshield/internal/agent/enroll"
	"github.com/lucianoengel/openshield/internal/agent/execguard"
	"github.com/lucianoengel/openshield/internal/agent/execipc"
	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/canary"
	"github.com/lucianoengel/openshield/internal/clipboard"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
	"github.com/lucianoengel/openshield/internal/enforcers/process"
	"github.com/lucianoengel/openshield/internal/enforcers/quarantine"
	usbenforce "github.com/lucianoengel/openshield/internal/enforcers/usb"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/fim"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/printguard"
	"github.com/lucianoengel/openshield/internal/retain"
	"github.com/lucianoengel/openshield/internal/store/postgres"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"github.com/lucianoengel/openshield/internal/transport/tlsconf"
	"github.com/nats-io/nats.go"
)

func main() {
	// PLAT-5 follow-up: validate every declared field before anything else. BOOTSTRAP-only, and here for a
	// CONSISTENCY reason as much as a capability one: D269 built a signed fleet-control channel on the
	// premise that endpoints do NOT read the configuration store, and making these dynamic would leave two
	// disagreeing answers to "how does an endpoint learn something fleet-wide".
	cfg := config.New(config.EngineFields, config.EnvSource{})
	if len(os.Args) > 1 && os.Args[1] == "config" {
		cfg.WriteEffective(os.Stdout)
		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "\n%v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "openshield-engine: %v\n", err)
		os.Exit(1)
	}

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

	// DLP-5b: compliance packs (OPENSHIELD_POLICY_PACK[S], + optional OPENSHIELD_POLICY_CUSTOM)
	// COMPOSE with the observe-only default under a most-restrictive-wins lattice (ADR-5) — selecting
	// a pack never disables the default's protections. An unknown pack aborts startup: a compliance
	// control must not silently fall back to a permissive policy.
	pol, err := policy.SelectFromEnv(ctx)
	if err != nil {
		fatal(log, "loading policy", err)
	}
	log.Info("policy loaded (DLP-5b: packs compose with the default)", slog.String("bundle", pol.Bundle()))

	// A WORKER POOL, sized by what will actually run concurrently.
	//
	// privileged.Worker.Classify holds a mutex for the whole request, so one worker serialises every
	// classification. That is correct for the async path — file events arrive one at a time from the
	// watcher — and wrong for the inline file-open gate, where the whole point of D356's concurrency is
	// that N blocked processes are decided in parallel. Measured: eight concurrent decisions take 54ms
	// against one worker and 11ms against a pool of eight.
	//
	// So the default follows the gate: one worker normally, and the gate's in-flight bound when the gate
	// is enabled. Making it automatic rather than a warning is deliberate — an operator who enables the
	// gate and misses a log line would get silently serialised decisions, which is the failure mode this
	// whole area keeps producing.
	poolSize := envInt("OPENSHIELD_WORKER_POOL", 0)
	if poolSize <= 0 {
		poolSize = 1
		if strings.TrimSpace(os.Getenv("OPENSHIELD_OPEN_IPC_SOCKET")) != "" {
			poolSize = openipc.DefaultMaxInFlight
		}
	}
	worker, err := privileged.StartPool(ctx, workerBin, poolSize)
	if err != nil {
		fatal(log, "starting worker pool", err)
	}
	defer worker.Close()
	if poolSize > 1 {
		log.Info("engine: worker pool", slog.Int("size", poolSize),
			slog.String("why", "concurrent classification; each worker is a separate sandboxed process"))
	}

	eng := engine.New(worker, pol, ledger, log, 30*time.Second)
	// PLAT-9: install the EMERGENCY DISABLE. The switch sits between the decision and the enforcer, so
	// classification, the policy and the ledger all still run and only the enforcement call is skipped:
	// STOP ACTING, KEEP SEEING. Implemented earlier it would destroy the record of what happened while
	// enforcement was off — exactly the period an operator will need to reconstruct. It fails toward
	// ENFORCING: absence of the break-glass file is never engagement.
	installKillSwitch(ctx, eng, log)

	// XDR-3: attribute endpoint events to this device by its canonical pseudonym, so
	// fanotify/execaudit events (which the connectors produce target-only) carry the
	// enrolled device identity and pass the event contract — and resolve to the XDR
	// entity (D195). Defaults to a stable id so events are always attributed.
	eng.SetSubject(env("OPENSHIELD_AGENT_ID", "engine"))

	// HON-3: register the file enforcers so the endpoint can CONTAIN a detection, not only
	// observe it. Observe-only by DEFAULT (D1) — registered ONLY when OPENSHIELD_ENFORCE is
	// set, mirroring the gateway's opt-in flow enforcer.
	if err := registerEnforcers(eng, log); err != nil {
		fatal(log, "registering enforcers", err)
	}

	// OPTIONAL fleet telemetry (D80): when NATS + an enrollment endpoint are
	// configured, enroll a signed identity and project real detections to the
	// control plane, so fleet visibility, peer-UEBA and the dead-man's-switch operate
	// over real endpoint detections. Off by default — the single-host observe path is
	// unchanged. Mirrors the gateway (D77).
	if natsURL, enrollURL := os.Getenv("OPENSHIELD_NATS_URL"), os.Getenv("OPENSHIELD_ENROLL_URL"); natsURL != "" && enrollURL != "" {
		agentID := env("OPENSHIELD_AGENT_ID", "engine")
		id, err := identity.Generate(agentID)
		if err != nil {
			fatal(log, "identity", err)
		}
		if err := enrollpkg.Enroll(ctx, http.DefaultClient, enrollURL, agentID, os.Getenv("OPENSHIELD_ENROLL_TOKEN"), id); err != nil {
			fatal(log, "enroll", err)
		}
		conn, err := nats.Connect(natsURL, natsOptions(log)...)
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
		// PLAT-2: durable ingest is the DEFAULT, so switch the publisher onto the JetStream stream. Before
		// this, only the fleet SIMULATOR did — meaning every real detection this binary produced went over
		// core NATS at-most-once while the platform claimed durable ingest. Fatal on failure: silently
		// degrading to at-most-once telemetry is the missing-evidence failure the durable path exists to fix.
		if err := natsx.EnableDurableIfDefault(pub); err != nil {
			fatal(log, "durable telemetry ingest", err)
		}
		eng.SetTelemetry(pub)
		log.Info("engine: fleet telemetry ENABLED — real detections project to the control plane (D80)",
			slog.String("agent_id", agentID), slog.Bool("durable_ingest", natsx.JetStreamEnabled()))
	}

	// The observe path needs no privileged agent. The engine opens a file watcher
	// over the configured directories (validated above) and runs each event through
	// the pipeline. The watcher is selected per-OS at build time (openFileWatcher):
	// Linux fanotify NOTIFY mode, UNPRIVILEGED (D52); a portable poll-based watcher
	// on windows/darwin so the same engine observes there too (ADR-11/PLAT-7).
	// Inline blocking (the privileged permission-mode agent) is deferred (D49).
	events := make(chan *corev1.Event, 64)
	var wg sync.WaitGroup
	opened := 0
	for _, dir := range dirs {
		w, err := openFileWatcher(dir)
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

	// Optional network source: the DNS query connector (NIPS-3). When OPENSHIELD_DNS_LISTEN
	// is set, live resolution enters the SAME pipeline as file events — additive to file
	// watching, and observe-only (D1). Tracked in wg so events is not closed while it produces.
	// DEPLOY: this listener NEVER answers a query — feed it a MIRROR/TAP of DNS traffic (SPAN/eBPF),
	// never an inline :53 redirect, which would blackhole the fleet's DNS (see deploy/README.md).
	if dnsAddr := strings.TrimSpace(os.Getenv("OPENSHIELD_DNS_LISTEN")); dnsAddr != "" {
		// The tunnelling threshold, REPORTED on the startup line below rather than only stored. A
		// threshold is the kind of setting whose typo disables a detector silently, so an operator has
		// to be able to read back the number the process is actually using.
		if v := strings.TrimSpace(os.Getenv("OPENSHIELD_DNS_TUNNEL_THRESHOLD")); v != "" {
			f, perr := strconv.ParseFloat(v, 64)
			if perr != nil || f < 0 || f >= 1 {
				fatal(log, "OPENSHIELD_DNS_TUNNEL_THRESHOLD", fmt.Errorf(
					"%q is not a value in [0,1) — a threshold the score cannot reach runs the detector "+
						"on every query and never alerts, while this line says it is enabled", v))
			}
			dns.SetTunnelThreshold(f)
		}
		dl, err := dnsListener(ctx, dnsAddr, events, log)
		if err != nil {
			fatal(log, "dns listen", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := dl.Serve(ctx); err != nil {
				log.Error("dns serve", slog.String("err", err.Error()))
			}
		}()
		// Its refusals are otherwise invisible: a rate-limited query never becomes an event, so it
		// cannot be missing from anything an operator would think to look at.
		wg.Add(1)
		go func() {
			defer wg.Done()
			reportDiscards(ctx, log, "dns", time.Minute,
				discardCounter{"rate_limited", dl.RateLimited},
				discardCounter{"unparsed", dl.Dropped})
		}()
		log.Info("engine: DNS connector ENABLED — live resolution enters the pipeline (NIPS-3)",
			slog.String("listen", dl.Addr().String()),
			slog.Float64("tunnel_threshold", dns.TunnelThreshold()))
	}

	// Optional email source: the SMTP capture connector (SMTP-1). The connector was complete and started
	// by nothing — no import, no setting — while the product described itself as inspecting SMTP.
	//
	// CHAINED into the content resolver rather than installed over it, the way the print socket chains
	// over the clipboard store: the resolver holds exactly ONE function, so an assignment here would
	// silently disable clipboard or print classification for anyone who enables both.
	if smtpAddr := strings.TrimSpace(os.Getenv("OPENSHIELD_SMTP_LISTEN")); smtpAddr != "" {
		sstore := clipboard.NewContentStore(nil)
		sprev := eng.ContentResolver()
		eng.SetContentResolver(func(ev *corev1.Event) []byte {
			if b := sstore.Resolve(ev.GetEventId()); len(b) > 0 {
				return b
			}
			if sprev != nil {
				return sprev(ev)
			}
			return nil
		})
		sl, err := smtpListener(ctx, smtpAddr, sstore, events, log)
		if err != nil {
			fatal(log, "smtp listen", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sl.Serve(ctx); err != nil {
				log.Error("smtp serve", slog.String("err", err.Error()))
			}
		}()
		// EVERY LIMIT NAMED AT STARTUP. Each is a way an operator can be wrong about what they just
		// enabled, and each surfaces late and badly otherwise: undelivered mail if this is mistaken for
		// an MTA, or a channel that silently inspects nothing if the clients negotiate TLS.
		wg.Add(1)
		go func() {
			defer wg.Done()
			reportDiscards(ctx, log, "smtp", time.Minute,
				discardCounter{"unparsed_sessions", sl.Dropped},
				discardCounter{"refused_connections", sl.Refused})
		}()
		log.Warn("engine: SMTP capture connector ENABLED — a message body is classified in the sandboxed "+
			"worker. This is a CAPTURE listener, NOT an MTA: point a journaling/archive flow or a tap at "+
			"it, never production mail delivery. It does NOT handle STARTTLS or implicit TLS, so a "+
			"session that negotiates TLS is not parsed. Observe-only (D1).",
			slog.String("listen", sl.Addr().String()))
	}

	// Optional exec-event source: the auditd exec connector (HIPS-5c). When OPENSHIELD_EXEC_AUDIT_LOG
	// names a readable stream (a tailed audit log, a fifo, or the audit socket), process executions
	// enter the SAME pipeline — additive, observe-only (D1) unless a KILL policy + OPENSHIELD_ENFORCE
	// are set. Tracked in wg so events is not closed while it produces.
	if execLog := strings.TrimSpace(os.Getenv("OPENSHIELD_EXEC_AUDIT_LOG")); execLog != "" {
		f, err := os.Open(execLog)
		if err != nil {
			fatal(log, "opening exec audit log", err)
		}
		defer f.Close()

		// A REGULAR FILE IS FOLLOWED. Handed straight to the scanner it would be drained once and
		// end at EOF — every execution before startup ingested, none after it, and no signal that it
		// happened. A fifo or socket already blocks correctly while a writer holds it open, so it is
		// left as it is.
		var src io.Reader = f
		mode := "read-once"
		if st, serr := f.Stat(); serr == nil && st.Mode().IsRegular() {
			src = execaudit.Follow(ctx, f, execLog, 0)
			mode = "following"
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := execSource(ctx, src, events, log)
			if err != nil {
				log.Error("exec source", slog.String("err", err.Error()))
				return
			}
			// THE SOURCE ENDED. On shutdown that is normal and silent; while the engine is still
			// running it is a loss of endpoint process visibility, and "no suspicious executions" then
			// reads exactly like "nothing was looked at" (D31).
			if ctx.Err() == nil {
				log.Warn("engine: exec source ENDED — no further process executions will be observed "+
					"on this endpoint. The engine keeps running; HIPS process detection does not.",
					slog.String("source", execLog), slog.String("mode", mode))
			}
		}()
		log.Info("engine: exec connector ENABLED — process executions enter the pipeline (HIPS-5)",
			slog.String("source", execLog), slog.String("mode", mode))
	}

	// Optional File Integrity Monitoring source (HIPS-4). When OPENSHIELD_FIM_PATHS names critical
	// files/dirs, the engine hashes them into a known-good baseline (OPENSHIELD_FIM_BASELINE, built +
	// saved on first run, loaded thereafter) and periodically rescans, emitting a drift Event
	// (modified/created/deleted) into the SAME pipeline so a tamper finding becomes an audited decision.
	// No privilege (periodic hashing). Tracked in wg so events is not closed while it produces.
	if fimPaths := splitEnv("OPENSHIELD_FIM_PATHS"); len(fimPaths) > 0 {
		baselineFile := strings.TrimSpace(os.Getenv("OPENSHIELD_FIM_BASELINE"))
		if baselineFile == "" {
			fatal(log, "FIM misconfigured", errNoFimBaseline)
		}
		var manifest *fim.Manifest
		if pubPath := strings.TrimSpace(os.Getenv("OPENSHIELD_FIM_BASELINE_PUBKEY")); pubPath != "" {
			// Verified mode (HIPS-4 inc 3): the baseline MUST be operator-signed and verify against the
			// trusted key. No auto-capture — a node must not mint and trust its own baseline (it could be
			// fed tampered files at capture). A missing/unsigned/invalid baseline is fatal.
			pub, err := readEd25519Pub(pubPath)
			if err != nil {
				fatal(log, "loading FIM baseline pubkey", err)
			}
			m, err := fim.LoadSignedManifest(baselineFile, pub)
			if err != nil {
				fatal(log, "verifying signed FIM baseline (sign it with openshield-fim-baseline)", err)
			}
			manifest = m
			log.Info("engine: FIM active against an OPERATOR-SIGNED baseline (tamper-evident)",
				slog.String("baseline", baselineFile), slog.Int("files", m.Size()))
		} else if _, statErr := os.Stat(baselineFile); statErr != nil {
			m, overflow, err := fim.BuildBaseline(fimPaths, fim.Options{})
			if err != nil {
				fatal(log, "building FIM baseline", err)
			}
			if err := fim.SaveManifest(baselineFile, m); err != nil {
				fatal(log, "saving FIM baseline", err)
			}
			manifest = m
			log.Warn("engine: FIM baseline CAPTURED from the current on-disk state — REVIEW it; the "+
				"manifest is UNSIGNED and NOT tamper-evident (an attacker who can write it can hide drift) "+
				"— set OPENSHIELD_FIM_BASELINE_PUBKEY + sign with openshield-fim-baseline",
				slog.String("baseline", baselineFile), slog.Int("files", m.Size()), slog.Int("skipped", overflow))
		} else {
			m, err := fim.LoadManifest(baselineFile)
			if err != nil {
				fatal(log, "loading FIM baseline", err)
			}
			manifest = m
			log.Warn("engine: FIM active against an UNSIGNED baseline (tamper-vulnerable) — "+
				"set OPENSHIELD_FIM_BASELINE_PUBKEY for a signed, tamper-evident baseline",
				slog.String("baseline", baselineFile), slog.Int("files", m.Size()))
		}
		iv := envDuration("OPENSHIELD_FIM_INTERVAL", 60*time.Second)
		wg.Add(1)
		go func() {
			defer wg.Done()
			fimSource(ctx, manifest, fimPaths, iv, fim.Options{}, events, log)
		}()
		log.Info("engine: FIM connector ENABLED — critical-file drift enters the pipeline (HIPS-4)",
			slog.Int("paths", len(fimPaths)), slog.Duration("interval", iv))
		// Real-time (HIPS-4 inc 2): fanotify-triggered immediate re-check so tamper is caught in ~ms,
		// not up to one poll interval late. Additive to the poll (which stays the completeness backstop).
		if os.Getenv("OPENSHIELD_FIM_REALTIME") != "" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fimWatchSource(ctx, manifest, fimPaths, fim.Options{}, envDuration("OPENSHIELD_FIM_DEBOUNCE", 200*time.Millisecond), events, log)
			}()
			log.Info("engine: FIM real-time watch ENABLED (poll remains the backstop)")
		}
	} else {
		log.Info("engine: FIM inert (set OPENSHIELD_FIM_PATHS + OPENSHIELD_FIM_BASELINE to enable)")
	}

	// Ransomware canary (HIPS-4): plant decoys in the configured dirs and fire a high-severity ransomware
	// event when a threshold of them change within a window (the mass-change signature). Each dir gets its
	// own detector + poll loop.
	if canaryDirs := splitEnv("OPENSHIELD_CANARY_DIRS"); len(canaryDirs) > 0 {
		count := envInt("OPENSHIELD_CANARY_COUNT", 16)
		det := &canary.Detector{
			Threshold: envInt("OPENSHIELD_CANARY_THRESHOLD", 4),
			Window:    envDuration("OPENSHIELD_CANARY_WINDOW", 10*time.Second),
		}
		iv := envDuration("OPENSHIELD_CANARY_INTERVAL", 2*time.Second)
		for _, dir := range canaryDirs {
			paths, err := canary.Plant(dir, count)
			if err != nil {
				fatal(log, "planting canaries", err)
			}
			m, _, err := fim.BuildBaseline(paths, fim.Options{})
			if err != nil {
				fatal(log, "baselining canaries", err)
			}
			d := dir
			mani := m
			cpaths := paths
			wg.Add(1)
			go func() {
				defer wg.Done()
				canarySource(ctx, mani, d, cpaths, det, iv, events, log)
			}()
			log.Info("engine: ransomware canary ACTIVE", slog.String("dir", d), slog.Int("canaries", len(paths)),
				slog.Int("threshold", det.Threshold), slog.Duration("window", det.Window))
		}
	}

	// Memory-injection detection (HIPS-4): poll running processes for writable+executable memory (the
	// W^X-violation injection signature) and emit a high-severity event per new suspect. A fleet-wide
	// scan needs root; unprivileged it covers the engine's own processes.
	// D1/T-020: observe USB attachments. Off unless an interval is configured — a poll on every endpoint
	// is a cost an operator opts into.
	if iv := envDuration("OPENSHIELD_USB_INTERVAL", 0); iv > 0 {
		key := usbPseudonymKey(log)
		wg.Add(1)
		go func() {
			defer wg.Done()
			usbSource(ctx, env("OPENSHIELD_AGENT_ID", "engine"), key, iv, events, log)
		}()
		log.Info("engine: USB observation ENABLED", slog.Duration("interval", iv))
	}

	if iv := envDuration("OPENSHIELD_MEMSCAN_INTERVAL", 0); iv > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			memScanSource(ctx, "/proc", iv, events, log)
		}()
		log.Info("engine: memory-injection scan ENABLED (W^X detection)", slog.Duration("interval", iv))
	}

	// DLP-2a: the CLIPBOARD exfil producer. Copy-paste is the channel a desktop user actually reaches for,
	// and watching directories while ignoring it is the gap "not a DLP without the exfil channels" names.
	//
	// The copied bytes reach the SANDBOXED WORKER through a content store chained into the engine's content
	// resolver; they never touch the Event (D10/D29) and the privileged agent is not involved (D13).
	// Disabled unless an interval is set, and it refuses to start LOUDLY when there is no display or no
	// helper binary — a producer that polls forever with nothing to see would be worse than none.
	if iv := envDuration("OPENSHIELD_CLIPBOARD_INTERVAL", 0); iv > 0 {
		excl := clipboard.NewExclusions(splitList(os.Getenv("OPENSHIELD_CLIPBOARD_EXCLUDE"))...)
		store := clipboard.NewContentStore(nil)
		eng.SetContentResolver(func(ev *corev1.Event) []byte { return store.Resolve(ev.GetEventId()) })

		// MEDIATION first (DLP-2a inc 2): on X11 the engine can own the selection and DECIDE each paste,
		// which is what enterprise DLP does. Falls back to observe-only capture when unavailable.
		mediating := false
		if clipboard.Detect() == clipboard.DisplayX11 && os.Getenv("OPENSHIELD_CLIPBOARD_MEDIATE") != "" {
			mediating = mediateClipboard(ctx, os.Getenv("DISPLAY"), store, excl,
				func(ev *corev1.Event, _ string) bool {
					dec, derr := eng.Process(ctx, ev)
					if derr != nil {
						// Fail SAFE for a clipboard: an evaluation failure must not silently mediate
						// (and thus block) content we never classified.
						log.Warn("clipboard: classification failed; not mediating this copy", slog.Any("err", derr))
						return false
					}
					return dec.GetAction() != corev1.Action_ACTION_ALLOW
				}, events, log)
		}

		reader, cerr := clipboard.NewReader()
		switch {
		case mediating:
			// Mediation owns capture; the polled producer would double-report.
		case cerr != nil:
			log.Warn("engine: clipboard monitoring UNAVAILABLE — not started (the engine runs without it)",
				slog.Any("err", cerr))
		default:
			log.Warn("engine: clipboard capabilities",
				slog.String("report", clipboard.PolledHelperCapabilities(reader.DisplayServer()).Summary()))
			wg.Add(1)
			go func() {
				defer wg.Done()
				clipboardSource(ctx, reader, store, excl, iv, events, log)
			}()
			log.Warn("engine: clipboard exfil monitoring ACTIVE — a copy is classified in the sandboxed "+
				"worker (observe/alert only; it does not block a paste)",
				slog.Duration("interval", iv), slog.String("display", reader.DisplayServer()))
		}
	}

	// DLP-2b: answer print-job verdicts for the CUPS filter. The filter sits in the spooler chain where a
	// non-zero exit ABORTS the job, so this is prevention, not reporting — and the filter parses nothing:
	// the job is classified here, in the sandboxed worker.
	if sock := strings.TrimSpace(os.Getenv("OPENSHIELD_PRINT_SOCKET")); sock != "" {
		pstore := clipboard.NewContentStore(nil)
		prev := eng.ContentResolver()
		eng.SetContentResolver(func(ev *corev1.Event) []byte {
			if b := pstore.Resolve(ev.GetEventId()); len(b) > 0 {
				return b
			}
			if prev != nil {
				return prev(ev)
			}
			return nil
		})
		psrv := &printguard.Server{
			Decide: printDecider(ctx, eng, pstore, events, log),
			Logf:   func(format string, a ...any) { log.Warn(fmt.Sprintf(format, a...)) },
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := psrv.Listen(ctx, sock); err != nil && ctx.Err() == nil {
				log.Error("engine: print-verdict server stopped (printing continues unchecked — the filter "+
					"fails open by design)", slog.Any("err", err))
			}
		}()
		log.Warn("engine: print DLP ACTIVE — a job is classified in the sandboxed worker and can be REFUSED "+
			"before it prints", slog.String("socket", sock))
	}

	// HIPS-3 increment 2a: serve exec verdicts to the PRIVILEGED gate over a unix socket. The gate holds
	// CAP_SYS_ADMIN and cannot parse anything, so it asks us — the unprivileged process that owns the
	// policy — for a verdict, and we answer DENY only when the pipeline decides DENY_EXEC.
	//
	// The DENY_EXEC semantics live in execguard (ExecEvaluator), not here: re-deriving "which actions
	// block an exec" at a second site is how two answers to one question start to drift.
	//
	// NOTE (honest scope): what makes this a FULL-PIPELINE verdict is that OPA decides it. Acting on a
	// signed CONTAIN Response-Intent needs SOAR-7, which does not exist yet — so this serves
	// policy-driven denials, not intent-driven containment.
	if sock := strings.TrimSpace(os.Getenv("OPENSHIELD_EXEC_IPC_SOCKET")); sock != "" {
		verdictSrv := &execipc.Server{
			Evaluate: execguard.ExecEvaluator{Decide: execguard.Decider(eng)}.Evaluate,
			Logf:     func(format string, a ...any) { log.Warn(fmt.Sprintf(format, a...)) },
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := verdictSrv.Listen(ctx, sock); err != nil && ctx.Err() == nil {
				// Not fatal: losing the verdict socket degrades the exec gate to its static path (and to
				// audited fail-opens), which is strictly better than taking the whole engine down.
				log.Error("engine: exec-verdict server stopped", slog.Any("err", err))
			}
		}()
		log.Warn("engine: exec-verdict IPC ACTIVE — the privileged gate's inline exec decisions now come "+
			"from this pipeline (policy-driven; intent-driven containment awaits SOAR-7)",
			slog.String("socket", sock))
	}

	// B2: answer the privileged FAN_OPEN_PERM gate's questions from this pipeline.
	//
	// The agent reads a bounded prefix from the kernel's descriptor and sends it; this side classifies
	// those bytes in the sandboxed worker and runs the same policy the async tier runs. It NEVER opens
	// the file — an open here would raise a second permission event the same gate must answer, which
	// deadlocks inside an uninterruptible window.
	//
	// A SEPARATE SOCKET from the exec gate's, so the two are independently enable-able: an operator may
	// reasonably want exec prevention without file-open prevention, whose availability cost is far
	// higher.
	if sock := strings.TrimSpace(os.Getenv("OPENSHIELD_OPEN_IPC_SOCKET")); sock != "" {
		// THE ACTION→VERDICT MAPPING LIVES HERE, in the process where corev1 already is. Putting it in
		// the IPC package would drag protobuf into the PRIVILEGED agent, which imports that package for
		// its client — the D13 boundary the build's agent-dependency check enforces.
		//
		// Only an action that MEANS refuse becomes a deny, listed explicitly rather than "anything that
		// is not ALLOW", so a new action added to the closed set does not silently become a reason to
		// block an open.
		od := prefilter.NewDecider(worker, pol, 0, 120*time.Millisecond, log)
		openSrv := &openipc.Server{
			Decide: func(ctx context.Context, path string, prefix []byte) (openipc.Verdict, error) {
				dec, derr := od.DecideBytes(ctx, path, prefix)
				if derr != nil {
					return openipc.VerdictAllow, derr
				}
				switch dec.GetAction() {
				case corev1.Action_ACTION_BLOCK, corev1.Action_ACTION_QUARANTINE_LOCAL:
					return openipc.VerdictDeny, nil
				}
				return openipc.VerdictAllow, nil
			},
			Logf: func(format string, a ...any) { log.Warn(fmt.Sprintf(format, a...)) },
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := openSrv.Listen(ctx, sock); err != nil && ctx.Err() == nil {
				// Not fatal, for the same reason the exec socket is not: losing it degrades the gate to
				// audited fail-opens, which is strictly better than taking the engine down and leaving
				// the endpoint with no pipeline at all.
				log.Error("engine: open-verdict server stopped", slog.Any("err", err))
			}
		}()
		log.Warn("engine: open-verdict IPC ACTIVE — the privileged file-open gate's inline decisions now "+
			"come from this pipeline. The verdict is made from a BOUNDED PREFIX, so content past the "+
			"ceiling is not seen inline; the async tier classifies the whole file and contains it "+
			"afterwards (D16).",
			slog.String("socket", sock))
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
			processOne(ctx, eng, ev, log)
		}
	}
}

// processOne runs one event through the engine, RECOVERING from any panic (ENG-2). The engine now
// ingests attacker-influenced events from network/exec sources, and a panic in a stage on one
// crafted event must be contained to that event — logged, the event dropped — never crash the
// engine and take down observation of the whole fleet.
func processOne(ctx context.Context, eng *engine.Engine, ev *corev1.Event, log *slog.Logger) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("recovered from panic processing event",
				slog.String("event", ev.GetEventId()), slog.Any("panic", r))
		}
	}()
	dec, err := eng.Process(ctx, ev)
	if err != nil {
		// A processing error is auditable, not silent (D17) — the engine's audit sink records the
		// outcome; here we surface it operationally.
		log.Error("process", slog.String("event", ev.GetEventId()), slog.String("err", err.Error()))
		return
	}
	if dec != nil {
		log.Info("decision",
			slog.String("event", ev.GetEventId()),
			slog.String("action", dec.GetAction().String()),
			slog.String("path", ev.GetFilesystem().GetResolvedPath()))
	}
}

// errNoWatchDirs makes an engine watching nothing fail loudly rather than run as
// a silent no-op.
var errNoWatchDirs = errors.New("set OPENSHIELD_WATCH_DIRS (comma-separated) to at least one directory")

// watchDirs parses OPENSHIELD_WATCH_DIRS (comma-separated), trimming blanks.
func watchDirs() []string { return splitEnv("OPENSHIELD_WATCH_DIRS") }

// splitEnv parses a comma-separated env var into a trimmed, non-empty list.
func splitEnv(key string) []string {
	var out []string
	for _, d := range strings.Split(os.Getenv(key), ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// errNoFimBaseline makes a FIM run without a baseline path fail loudly (the baseline is
// where the known-good state lives — without a persistent file it cannot survive a restart).
var errNoFimBaseline = errors.New("set OPENSHIELD_FIM_BASELINE to a manifest file path when OPENSHIELD_FIM_PATHS is set")

// envInt parses an integer env var, returning def when unset or malformed.
func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// readEd25519Pub reads a raw 32-byte Ed25519 public key (the trusted operator key for verifying a
// signed FIM baseline).
func readEd25519Pub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %s is %d bytes, want %d", path, len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// watch feeds a directory's fanotify events into the shared channel until the
// context is cancelled. A read error that is not cancellation is logged and the
// watch continues — a transient error must not silently stop observation.
func watch(ctx context.Context, log *slog.Logger, w fileWatcher, dir string, out chan<- *corev1.Event, wg *sync.WaitGroup) {
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

// registerEnforcers wires the file enforcers into the engine when OPENSHIELD_ENFORCE is set,
// so a decision CONTAINS (not only observes) — the HON-3 fix (production was observe-only
// because no binary ever populated engine.Enforcers). Without the flag the engine gets NO
// enforcers (observe-only default, D1). QUARANTINE_LOCAL is always registered when enforcing;
// ENCRYPT_LOCAL is registered on top when a key (symmetric) or recipient pubkey (escrow, D59)
// is configured. Containment is post-decision (D16), not prevention.
func registerEnforcers(eng *engine.Engine, log *slog.Logger) error {
	// D1/T-020: the USB posture enforcer, registered only when an operator asks for it (D313).
	//
	// It was built with the producer and never registered by any binary, so a BLOCK decision on a USB
	// event had nothing to carry it out — the capability spec claimed "an actual enforcement point" and
	// there was none. Registering it unconditionally would have been wrong in the other direction: it
	// writes `authorized_default` on every USB controller, which needs root and changes how the WHOLE
	// MACHINE treats newly attached devices. That is a deployment decision, so it is a deliberate
	// setting rather than a consequence of enabling enforcement generally.
	//
	// IT IS DELIBERATELY NOT GATED ON OPENSHIELD_ENFORCE. Device control is a distinct posture from file
	// containment, and "hardware policy on, files observe-only" is a real and common way to roll this
	// out — a rollout OPENSHIELD_ENFORCE would otherwise make impossible. Suppression still applies:
	// the kill switch is checked in Engine.Enforce, before any enforcer runs, so break-glass stops this
	// one exactly as it stops the others.
	//
	// The global posture is the honest limit and worth stating: the kernel switch is per-CONTROLLER, not
	// per-device, so BLOCK deauthorises every subsequently attached device — including the operator's
	// keyboard. A per-device posture needs a udev rule per device id, which this does not attempt.
	if os.Getenv("OPENSHIELD_USB_ENFORCE") != "" {
		eng.Enforcers = append(eng.Enforcers, usbenforce.New(usbenforce.SysfsAuthorizer{
			Root: os.Getenv("OPENSHIELD_USB_SYSFS"),
		}))
		log.Info("engine: usb-posture(authorized_default) enforcer registered — a BLOCK on a USB event " +
			"deauthorises EVERY subsequently attached device on this machine, not only the one that " +
			"triggered it")
	}
	if os.Getenv("OPENSHIELD_ENFORCE") == "" {
		log.Info("engine: observe-only (set OPENSHIELD_ENFORCE to register file enforcers)")
		return nil
	}
	qdir := env("OPENSHIELD_QUARANTINE_DIR", "/var/lib/openshield/quarantine")
	eng.Enforcers = append(eng.Enforcers, quarantine.New(qdir))
	names := []string{"quarantine→" + qdir}

	if keyPath := os.Getenv("OPENSHIELD_ENCRYPT_KEY"); keyPath != "" {
		enc, err := encryptlocal.New(keyPath)
		if err != nil {
			return err
		}
		eng.Enforcers = append(eng.Enforcers, enc)
		names = append(names, "encrypt-local")
	} else if pubPath := os.Getenv("OPENSHIELD_ENCRYPT_PUBKEY"); pubPath != "" {
		enc, err := encryptlocal.NewEscrow(pubPath)
		if err != nil {
			return err
		}
		eng.Enforcers = append(eng.Enforcers, enc)
		names = append(names, "encrypt-local(escrow)")
	}
	// HIPS containment (HIPS-5): KILL_PROCESS terminates a process by pid POST-exec — a real,
	// runnable containment now that the engine selects the pid target by event kind.
	//
	// DENY_EXEC (true inline exec-block, HIPS-3) is answered by the WATCHDOG's inline path, NOT an
	// engine enforcer: the watchdog's ExecEvaluator runs engine.Process over the exec-permission
	// event (internal/agent/execguard.Decider) and maps DENY_EXEC → VerdictBlock → Responder.Deny,
	// reusing the fail-open budget. The process.DenyEnforcer is therefore deliberately NOT registered
	// here — the engine's enforce() loop fires inside engine.Process, so registering it would DOUBLE
	// the deny (once via the enforcer, once via the watchdog's kernel answer). It remains for the
	// alternate async flow-enforcer model (an engine that dispatches exec events without holding the
	// permission fd). The privileged FAN_OPEN_EXEC_PERM producer that feeds the watchdog is the
	// root-gated adapter, deferred exactly like the inline file responder (B2) and NIPS-1 TPROXY.
	eng.Enforcers = append(eng.Enforcers, process.NewKillEnforcer())
	names = append(names, "kill-process")
	log.Warn("engine: ENFORCEMENT ENABLED — decisions now CONTAIN, not only observe (HON-3)",
		slog.Any("enforcers", names))
	return nil
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

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// installKillSwitch gives this endpoint the EMERGENCY DISABLE (PLAT-9), local and fleet-wide.
//
// The switch sits between the decision and the enforcer, so classification, the policy and the ledger all
// still run and only the enforcement call is skipped: STOP ACTING, KEEP SEEING. Implemented any earlier it
// would destroy the record of what happened while enforcement was off — exactly the period an operator
// will need to reconstruct. It fails toward ENFORCING: absence of the break-glass file is never
// engagement, or a permissions change silently turns the product off across a fleet.
//
// The fleet subscription is INDEPENDENT OF ENROLLMENT, and deliberately not folded into the telemetry
// connection above it. Being able to be DISABLED must not depend on being able to PUBLISH: an endpoint
// that failed to enrol is not the one that should be impossible to stop.
func installKillSwitch(ctx context.Context, eng *engine.Engine, log *slog.Logger) {
	eng.KillSwitch = core.Install(ctx.Done(), env("OPENSHIELD_BREAK_GLASS", core.BreakGlassFile),
		envDuration("OPENSHIELD_BREAK_GLASS_POLL", 10*time.Second),
		func(engaged bool, reason, source string) {
			if engaged {
				log.Warn("ENFORCEMENT DISABLED — detection and audit continue, nothing is being enforced",
					slog.String("reason", reason), slog.String("source", source))
				return
			}
			log.Warn("enforcement RESTORED", slog.String("source", source))
		})

	natsURL, keyPath := os.Getenv("OPENSHIELD_NATS_URL"), os.Getenv("OPENSHIELD_CONTROL_PLANE_KEY")
	if natsURL == "" || keyPath == "" {
		log.Warn("engine: no fleet-wide enforcement control (needs OPENSHIELD_NATS_URL and " +
			"OPENSHIELD_CONTROL_PLANE_KEY) — the only way to stop this endpoint enforcing is its local " +
			"break-glass file")
		return
	}
	key, err := core.LoadPublicKey(keyPath)
	if err != nil {
		fatal(log, "control-plane key", err)
	}
	conn, err := nats.Connect(natsURL, natsOptions(log)...)
	if err != nil {
		fatal(log, "fleet-control nats", err)
	}
	if _, err := eng.SubscribeFleetControl(conn, key); err != nil {
		fatal(log, "fleet-control subscribe", err)
	}
	// XDR-6: consume coordinated-response intents, so a CONTAINed subject's next exec is refused INLINE
	// by the local policy rather than after the fact.
	eng.SetIntentObserver(func(in *corev1.ResponseIntent) {
		log.Warn("coordinated-response intent APPLIED", slog.String("verb", in.GetVerb().String()),
			slog.String("subject", in.GetSubject()), slog.String("intent_id", in.GetIntentId()))
	})
	if _, err := eng.SubscribeIntents(conn, key); err != nil {
		fatal(log, "intent subscribe", err)
	}
	log.Info("engine: coordinated-response intents ACTIVE (XDR-6) — verified against the control-plane " +
		"key; the local policy decides what a verb means")
	go func() { <-ctx.Done(); conn.Close() }()
	log.Info("engine: fleet-wide enforcement control ACTIVE (PLAT-9) — signed, replay-bounded and " +
		"expiring; a refused control leaves enforcement ON")
}

// natsOptions builds the broker connection options from this process's TLS configuration.
//
// D294 FOUND THAT NONE OF THIS BINARY'S BROKER CONNECTIONS PRESENTED A CLIENT CERTIFICATE. D55 makes
// mutual TLS a property of the agent-facing channels, the control plane enforces it on its side, and
// this end connected in plaintext — so against a mutually-authenticated broker every channel failed, and
// because the fleet-control connection is fatal, the process would not start at all. A deployment could
// have mTLS or a kill switch, not both.
//
// Loaded per call rather than threaded through, because it is read a handful of times at startup and a
// parameter would have to reach four call sites in two files to fix a bug that is about all of them.
func natsOptions(log *slog.Logger) []nats.Option {
	cfg, err := tlsconf.LoadFromEnv()
	if err != nil {
		fatal(log, "TLS configuration", err)
	}
	if cfg == nil {
		return nil
	}
	return []nats.Option{nats.Secure(cfg.ClientConfig())}
}
