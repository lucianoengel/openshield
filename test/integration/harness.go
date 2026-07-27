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
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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
	t       *testing.T
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
	return fmt.Sprintf("osint-%s-%s-%d", role, strings.ToLower(safe), time.Now().UnixNano()%1e6)
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

// StartStack brings up Postgres and NATS on ephemeral ports and returns their addresses.
func StartStack(t *testing.T) *Stack {
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
	s.DSN = fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable", pgUser, pgPassword, pgPort, pgDatabase)

	natsName := uniqueName(t, "nats")
	// -js because durable ingest is the DEFAULT (PLAT-2): a producer started against a JetStream-less
	// broker fails fast by design, so a harness without it would be testing the opt-out path by accident.
	run(t, "podman", "run", "-d", "--rm", "--name", natsName,
		"-p", "127.0.0.1::4222", natsImage, "-js")
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", natsName).Run() })
	natsPort := hostPort(t, natsName, "4222/tcp")
	s.NATSURL = "nats://127.0.0.1:" + natsPort

	waitTCP(t, "127.0.0.1:"+pgPort, 60*time.Second)
	waitTCP(t, "127.0.0.1:"+natsPort, 60*time.Second)
	// A listening socket is not a ready database: Postgres accepts connections briefly before it will
	// serve queries, and a harness that raced that would fail in a way that looks like a product bug.
	waitPostgresReady(t, pgName, 60*time.Second)
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

// Binary builds the named command if needed and returns its path.
func Binary(t *testing.T, name string) string {
	t.Helper()
	buildOnce.Do(func() {
		binDir, buildErr = os.MkdirTemp("", "openshield-integration-bin")
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
	Cmd    *exec.Cmd
	Name   string
	output *syncBuffer
	t      *testing.T
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
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("---- %s output ----\n%s", name, out.String())
		}
	})
	return p
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
