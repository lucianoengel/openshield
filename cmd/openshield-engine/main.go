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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	enrollpkg "github.com/lucianoengel/openshield/internal/agent/enroll"
	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
	"github.com/lucianoengel/openshield/internal/enforcers/process"
	"github.com/lucianoengel/openshield/internal/enforcers/quarantine"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/fim"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/retain"
	"github.com/lucianoengel/openshield/internal/store/postgres"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"github.com/nats-io/nats.go"
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

	worker, err := privileged.StartWorker(ctx, workerBin)
	if err != nil {
		fatal(log, "starting worker", err)
	}
	defer worker.Close()

	eng := engine.NewFromWorker(worker, pol, ledger, log, 30*time.Second)

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
		eng.SetTelemetry(pub)
		log.Info("engine: fleet telemetry ENABLED — real detections project to the control plane (D80)",
			slog.String("agent_id", agentID))
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
		log.Info("engine: DNS connector ENABLED — live resolution enters the pipeline (NIPS-3)",
			slog.String("listen", dl.Addr().String()))
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := execSource(ctx, f, events, log); err != nil {
				log.Error("exec source", slog.String("err", err.Error()))
			}
		}()
		log.Info("engine: exec connector ENABLED — process executions enter the pipeline (HIPS-5)",
			slog.String("source", execLog))
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
