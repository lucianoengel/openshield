//go:build integration

// Package integration runs OpenShield's components as REAL PROCESSES against REAL infrastructure.
//
// Everything else in this repository tests a package. That leaves a specific and dangerous gap: the wiring
// in cmd/ — which environment variable reaches which constructor, which loop is started under the leader,
// which subscription is registered — is exercised by nothing. Those are exactly the defects that do not
// show up until a deployment, because every unit involved passes on its own.
//
// So this harness starts Postgres and NATS in containers, builds the actual binaries, runs them as
// subprocesses, and asserts on what crosses the boundaries between them.
//
// TWO DESIGN RULES, both learned from the existing shell e2e scripts failing on this very machine:
//
//  1. EPHEMERAL PORTS, ALWAYS. Those scripts bind fixed ports (55432, 4222), so they collide with any
//     standing development container and fail with "address already in use" — which reads as a broken test
//     rather than a busy machine, and is why they stopped being run. Every container here takes a
//     kernel-assigned port that the harness discovers.
//  2. EPHEMERAL NAMES AND FULL TEARDOWN. Containers are named per-run and removed on exit, so a crashed
//     run never poisons the next one.
//
// The suite SKIPS without podman rather than failing, so `make all` stays green on a machine that lacks
// it — the same shape as the other environment-gated tests here.
package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	postgresImage = "docker.io/library/postgres:16"
	natsImage     = "docker.io/library/nats:2"
	pgUser        = "openshield"
	pgPassword    = "integration" // ephemeral container, torn down per run
	pgDatabase    = "openshield"
)

// Stack is a running set of infrastructure for one test.
type Stack struct {
	DSN     string
	NATSURL string
	// hostPort is the Postgres address, kept so an additional database can be addressed on the same
	// container without re-parsing the DSN.
	hostPort string
	t        *testing.T
}

// requirePodman skips unless containers are available.
func requirePodman(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENSHIELD_SKIP_INTEGRATION") != "" {
		t.Skip("OPENSHIELD_SKIP_INTEGRATION set")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman unavailable: the integration suite runs real components against real infrastructure")
	}
}

// run executes a command and returns its combined output, failing the test on error.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// uniqueName gives every container a per-run identity, so a crashed run never collides with the next.
func uniqueName(t *testing.T, role string) string {
	t.Helper()
	safe := strings.NewReplacer("/", "-", " ", "-", "#", "-").Replace(t.Name())
	if len(safe) > 40 {
		safe = safe[:40]
	}
	return fmt.Sprintf(containerPrefix+"%s-%s-%d", role, strings.ToLower(safe), time.Now().UnixNano()%1e6)
}

// hostPort discovers the kernel-assigned host port for a container's exposed port.
func hostPort(t *testing.T, container, containerPort string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("podman", "port", container, containerPort).CombinedOutput()
		if err == nil {
			line := strings.TrimSpace(string(out))
			if i := strings.LastIndex(line, ":"); i >= 0 && i+1 < len(line) {
				return strings.TrimSpace(line[i+1:])
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("could not discover the host port for %s %s", container, containerPort)
	return ""
}

// ONE POSTGRES CONTAINER FOR THE WHOLE PACKAGE, one DATABASE per scenario.
//
// Starting a Postgres container per scenario was costing more than the scenarios: the image initialises,
// shuts down and restarts before it serves, and doing that forty-odd times in one run starved the
// machine badly enough that two scenarios which pass alone failed under `make all` — the control plane
// was not listening after sixty seconds.
//
// The instinct is to raise the timeout. That is the move D284 recorded as wrong: it would make the
// failures slower to arrive without making them rarer. The load is the defect, so the load is what
// changed. Isolation is preserved where it matters — every scenario still gets its own DATABASE, so no
// scenario sees another's rows, and the forward-secure ledger's per-signer chain is unaffected.
//
// NATS stays per-scenario: its subjects are fixed constants, so a shared broker would let one scenario's
// telemetry arrive in another's control plane. It is also the cheap half — it starts in well under a
// second.
var (
	pgOnce sync.Once
	pgAddr string
	pgErr  error
	pgSeq  atomic.Uint64
)

// sharedPostgres starts the package's single Postgres, once.
func sharedPostgres(t *testing.T) string {
	t.Helper()
	pgOnce.Do(func() {
		name := fmt.Sprintf(containerPrefix+"shared-pg-%d", time.Now().UnixNano()%1e9)
		out, err := exec.Command("podman", "run", "-d", "--rm", "--name", name,
			"-e", "POSTGRES_USER="+pgUser, "-e", "POSTGRES_PASSWORD="+pgPassword,
			"-e", "POSTGRES_DB="+pgDatabase,
			"-p", "127.0.0.1::5432", postgresImage).CombinedOutput()
		if err != nil {
			pgErr = fmt.Errorf("starting the shared postgres: %v\n%s", err, out)
			return
		}
		sharedPGName = name
		port := hostPort(t, name, "5432/tcp")
		pgAddr = "127.0.0.1:" + port
		waitTCP(t, pgAddr, 90*time.Second)
		waitPostgresReady(t, name, 90*time.Second)
		waitPostgresQueryable(t, fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
			pgUser, pgPassword, pgAddr, pgDatabase))
	})
	if pgErr != nil {
		t.Fatalf("%v", pgErr)
	}
	return pgAddr
}

// sharedPGName is removed by TestMain; a t.Cleanup would tear it down after the first scenario.
var sharedPGName string

// newDatabase creates a fresh database on the shared server and returns its DSN.
func newDatabase(t *testing.T, addr string) string {
	t.Helper()
	admin := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", pgUser, pgPassword, addr, pgDatabase)
	pool, err := pgxpool.New(Ctx(t), admin)
	if err != nil {
		t.Fatalf("connecting to the shared postgres: %v", err)
	}
	defer pool.Close()
	name := fmt.Sprintf("osint_%d", pgSeq.Add(1))
	if _, err := pool.Exec(Ctx(t), `CREATE DATABASE "`+name+`"`); err != nil {
		t.Fatalf("creating %s: %v", name, err)
	}
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", pgUser, pgPassword, addr, name)
}

// StartStack brings up the scenario's infrastructure: a database on the shared Postgres, and its own
// NATS broker.
func StartStack(t *testing.T) *Stack {
	t.Helper()
	requirePodman(t)
	s := &Stack{t: t}
	s.hostPort = sharedPostgres(t)
	s.DSN = newDatabase(t, s.hostPort)

	natsName := uniqueName(t, "nats")
	// -js because durable ingest is the DEFAULT (PLAT-2): a producer started against a JetStream-less
	// broker fails fast by design, so a harness without it would be testing the opt-out path by accident.
	run(t, "podman", "run", "-d", "--rm", "--name", natsName,
		"-p", "127.0.0.1::4222", natsImage, "-js")
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", natsName).Run() })
	natsPort := hostPort(t, natsName, "4222/tcp")
	s.NATSURL = "nats://127.0.0.1:" + natsPort

	waitTCP(t, "127.0.0.1:"+natsPort, 60*time.Second)
	return s
}

func waitTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s after %s", addr, timeout)
}

func waitPostgresReady(t *testing.T, container string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := exec.Command("podman", "exec", container, "pg_isready", "-U", pgUser).Run(); err == nil {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("postgres in %s never became ready", container)
}

// binaries are built ONCE per test binary run and shared: building twelve commands per scenario would
// dominate the suite's runtime and discourage adding scenarios, which is how an integration suite stops
// growing.
var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

// BinDirEnv names a directory of PRE-BUILT binaries, used instead of compiling.
//
// It exists for the rooted VM (kernel scenarios need real root, which this build host does not have and
// must not have). The VM has no Go toolchain, so the workflow is: build here, copy the binaries and the
// compiled test binary over, and run there. Without this the suite would silently skip on the one host
// where the privileged paths can actually be exercised.
const BinDirEnv = "OPENSHIELD_INTEGRATION_BIN_DIR"

// containerPrefix marks every container this suite starts, so the cleanup guard can tell one of ours from
// an operator's own — removing a container we did not start would be a test that damages its host, which
// is the thing this whole area is about.
const containerPrefix = "osint-"

// buildDirPrefix names the per-run build directory. A CONSTANT because the cleanup guard has to recognise
// one, and a prefix duplicated as a literal in two places is one rename away from a guard that silently
// stops matching anything.
const buildDirPrefix = "openshield-integration-bin"

// Binary builds the named command if needed and returns its path.
func Binary(t *testing.T, name string) string {
	t.Helper()
	if dir := os.Getenv(BinDirEnv); dir != "" {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s=%s but %s is not there: %v", BinDirEnv, dir, name, err)
		}
		return p
	}
	buildOnce.Do(func() {
		binDir, buildErr = os.MkdirTemp("", buildDirPrefix)
		if buildErr != nil {
			return
		}
		root, err := repoRoot()
		if err != nil {
			buildErr = err
			return
		}
		cmd := exec.Command("go", "build", "-o", binDir, "./cmd/...")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("building commands: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatalf("%v", buildErr)
	}
	p := filepath.Join(binDir, name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("built binary %s not found: %v", name, err)
	}
	return p
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// test/integration → repo root
	return filepath.Abs(filepath.Join(wd, "..", ".."))
}

// Process is a running OpenShield binary under test.
type Process struct {
	Cmd      *exec.Cmd
	Name     string
	output   *syncBuffer
	t        *testing.T
	stopOnce sync.Once
}

// syncBuffer collects a process's output safely from the reader goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// Start runs a built binary with the given environment, and stops it when the test ends.
//
// The process's output is captured and DUMPED ON FAILURE. An integration failure whose cause is in a
// subprocess's stderr, with the stderr discarded, is a failure nobody can diagnose — which is the second
// way an integration suite stops being used.
func Start(t *testing.T, name string, env []string, args ...string) *Process {
	t.Helper()
	bin := Binary(t, name)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", name, err)
	}
	p := &Process{Cmd: cmd, Name: name, output: out, t: t}
	t.Cleanup(func() {
		// SIGTERM FIRST, and the reason is not politeness. A process killed with SIGKILL never runs its
		// shutdown path — and shutdown is where this product removes the firewall rules it installed,
		// persists baselines and closes ledgers. A suite that only ever SIGKILLs leaves host state behind
		// (the DNS-redirect scenario left a nat rule pointing at a dead port, which then broke the NEXT
		// run) and never exercises teardown at all, which is a real code path with real failure modes.
		p.Stop()
		if t.Failed() {
			t.Logf("---- %s output ----\n%s", name, out.String())
		}
	})
	return p
}

// Stop terminates the process GRACEFULLY and waits for it, so a scenario can assert on what teardown
// did. Idempotent.
//
// It exists because `t.Cleanup` runs LIFO: a cleanup registered after Start's runs BEFORE it, so a
// scenario that checked host state in a cleanup was checking it while the process was still running.
// Teardown is a real code path — this product removes firewall rules in it — and asserting on it needs
// the stop to be an explicit step, not a side effect of the test ending.
func (p *Process) Stop() {
	p.t.Helper()
	p.stopOnce.Do(func() {
		_ = p.Cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = p.Cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = p.Cmd.Process.Kill()
			<-done
		}
	})
}

// Output is everything the process has written so far.
func (p *Process) Output() string { return p.output.String() }

// WaitForOutput blocks until the process's output contains want, or fails.
//
// Waiting on a LOG LINE rather than a fixed sleep is deliberate: a sleep long enough to be reliable on a
// loaded machine makes the suite slow, and one short enough to be fast makes it flaky. A process that
// announces readiness is the thing to wait for.
func (p *Process) WaitForOutput(want string, timeout time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(p.Output(), want) {
			return
		}
		if p.Cmd.ProcessState != nil && p.Cmd.ProcessState.Exited() {
			p.t.Fatalf("%s exited before printing %q\n%s", p.Name, want, p.Output())
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.t.Fatalf("%s did not print %q within %s\n%s", p.Name, want, timeout, p.Output())
}

// Eventually retries cond until it holds or the deadline passes.
func Eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", timeout, what)
}

// Ctx is a context bounded by the test's own deadline.
func Ctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// runCapture runs a binary to completion and returns its combined output and exit error. Used for
// subcommands, which are the operator-facing surface and are otherwise covered by nothing.
func runCapture(t *testing.T, name string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(Binary(t, name), args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// contains is a readability helper; the assertions read better than strings.Contains inline.
func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// freePort asks the kernel for an unused port and releases it. There is an inherent race between
// releasing and the process binding, but it is far smaller than the collision rate of fixed ports — which
// is the failure mode that took the shell e2e scripts out of service.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("parsing the assigned address: %v", err)
	}
	return port
}

// scanRow runs a single-row query, returning whether the row was there.
//
// A "no rows" result is false — the row has not appeared YET, which is what a poll loop wants. ANY OTHER
// error fails the test immediately, and that distinction is the whole point of the helper.
//
// It exists because of a bug it would have caught: a scenario polled `SELECT id, severity FROM incidents`
// inside Eventually, and `incidents` has no severity column — severity is DERIVED. Every poll errored
// identically to "not there yet", so the test waited the full ninety seconds and reported the chain as
// broken. A condition that can never be true is indistinguishable from one that has not happened, unless
// something looks at the error.
func scanRow(t *testing.T, pool *pgxpool.Pool, sql string, args []any, dest ...any) bool {
	t.Helper()
	err := pool.QueryRow(Ctx(t), sql, args...).Scan(dest...)
	switch {
	case err == nil:
		return true
	case errors.Is(err, pgx.ErrNoRows):
		return false
	default:
		t.Fatalf("querying %q: %v — this is a broken query, not a condition that has not happened yet", sql, err)
		return false
	}
}

// DSNFor creates an additional database in the stack's Postgres and returns a DSN for it.
//
// Needed because the forward-secure ledger's hash chain is bound to the signer that started it: two
// components sharing one database means the second one opens a chain whose keys it does not hold, and
// refuses to start — correctly, since continuing would either fork the chain or forge it. In a real
// deployment they are separate hosts; here they need separate databases to be separate hosts.
func (s *Stack) DSNFor(t *testing.T, name string) string {
	t.Helper()
	pool, err := pgxpool.New(Ctx(t), s.DSN)
	if err != nil {
		t.Fatalf("connecting to create %s: %v", name, err)
	}
	defer pool.Close()
	// The name is a test-supplied constant, never external input; quoted anyway because an identifier
	// cannot be a bind parameter and "it is a constant today" is how that stops being true.
	if _, err := pool.Exec(Ctx(t), `CREATE DATABASE "`+strings.ReplaceAll(name, `"`, "")+`"`); err != nil {
		t.Fatalf("creating database %s: %v", name, err)
	}
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", pgUser, pgPassword, s.hostPort, name)
}

// TLSMaterial is a CA plus one leaf certificate, as file paths.
type TLSMaterial struct{ CA, Cert, Key string }

// StartStackTLS brings up the stack with a MUTUAL-TLS NATS broker.
//
// Needed because D55 makes TLS a property of the PROCESS, not of one channel: configuring
// OPENSHIELD_TLS_* to get a mutually-authenticated HTTP surface also requires the broker connection to
// be mutually authenticated, and the control plane exits rather than silently falling back to plaintext.
// That is the right behaviour — a partial TLS configuration that half-applied would be worse than either
// extreme — but it means a scenario about operator certificates cannot use a plaintext broker.
//
// The certificate is the CALLER'S, deliberately: the broker and the control plane must be verifiable
// against the same CA the operators are, or the test would be proving something about a second trust
// root that no deployment has.
func StartStackTLS(t *testing.T, m TLSMaterial) *Stack {
	t.Helper()
	requirePodman(t)
	s := &Stack{t: t}

	pgName := uniqueName(t, "pg")
	run(t, "podman", "run", "-d", "--rm", "--name", pgName,
		"-e", "POSTGRES_USER="+pgUser, "-e", "POSTGRES_PASSWORD="+pgPassword,
		"-e", "POSTGRES_DB="+pgDatabase,
		"-p", "127.0.0.1::5432", postgresImage)
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", pgName).Run() })
	pgPort := hostPort(t, pgName, "5432/tcp")
	s.hostPort = "127.0.0.1:" + pgPort
	s.DSN = fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", pgUser, pgPassword, s.hostPort, pgDatabase)

	// The broker reads its material from a directory mounted read-only. Copied rather than mounted from
	// the caller's temp dir so the container sees world-readable files regardless of how the test's
	// TempDir is permissioned — a rootless podman mount inherits the host mode, and a 0600 key the
	// container user cannot read fails as an unhelpful handshake error much later.
	tlsDir := t.TempDir()
	for name, src := range map[string]string{"ca.pem": m.CA, "cert.pem": m.Cert, "key.pem": m.Key} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("reading %s: %v", src, err)
		}
		if err := os.WriteFile(filepath.Join(tlsDir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(tlsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	natsName := uniqueName(t, "nats")
	run(t, "podman", "run", "-d", "--rm", "--name", natsName,
		"-v", tlsDir+":/tls:ro,Z",
		"-p", "127.0.0.1::4222", natsImage,
		"-js", "--tls", "--tlscert", "/tls/cert.pem", "--tlskey", "/tls/key.pem", "--tlscacert", "/tls/ca.pem")
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", natsName).Run() })
	natsPort := hostPort(t, natsName, "4222/tcp")
	s.NATSURL = "nats://127.0.0.1:" + natsPort

	waitTCP(t, s.hostPort, 60*time.Second)
	waitTCP(t, "127.0.0.1:"+natsPort, 60*time.Second)
	waitPostgresReady(t, pgName, 60*time.Second)
	waitPostgresQueryable(t, s.DSN)
	return s
}

// waitPostgresQueryable connects OVER TCP and runs a query, retrying until it succeeds.
//
// pg_isready is not sufficient, and the reason is the same one D284 recorded about waiting on the
// wrong signal. The official Postgres image starts the server, runs initialisation, shuts it down and
// starts it again; `pg_isready` inside the container can answer YES during that first phase, and a
// client that connects then gets its connection RESET when the server restarts. The only signal that
// means "this database will serve my next query" is a query, from where the caller sits.
func waitPostgresQueryable(t *testing.T, dsn string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			var one int
			last = pool.QueryRow(ctx, `SELECT 1`).Scan(&one)
			pool.Close()
			if last == nil && one == 1 {
				cancel()
				return
			}
		} else {
			last = err
		}
		cancel()
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("postgres never became queryable at %s: %v", dsn, last)
}
