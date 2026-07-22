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
	"github.com/lucianoengel/openshield/internal/connectors/fanotify"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
	"github.com/lucianoengel/openshield/internal/enforcers/process"
	"github.com/lucianoengel/openshield/internal/enforcers/quarantine"
	"github.com/lucianoengel/openshield/internal/engine"
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
	// runnable containment now that the engine selects the pid target by event kind. DENY_EXEC
	// (true inline exec-block) is DEFERRED: it needs an exec-permission handler
	// (FAN_OPEN_EXEC_PERM), which is privileged and env-gated like the inline file responder (B2);
	// there is no ExecController to wire until that lands, so the deny enforcer is not registered.
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
