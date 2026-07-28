//go:build linux

package execipc_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lucianoengel/openshield/internal/agent/execguard"
	"github.com/lucianoengel/openshield/internal/agent/execipc"
	"github.com/lucianoengel/openshield/internal/agent/execmon"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
	"github.com/lucianoengel/openshield/internal/policy"
)

// The REAL-KERNEL test for HIPS-3 increment 2a: an exec is refused by the kernel because a verdict came
// back over the IPC socket, and allowed when the verdict says allow.
//
// What is REAL here: the fanotify FAN_OPEN_EXEC_PERM producer (execmon), the watchdog and its budget, the
// fanotify responder writing the kernel answer, the execipc client and server over a real unix socket, and
// execguard's DENY_EXEC→block mapping. What is STUBBED: the policy engine behind execguard.Decider — a
// full engine needs a worker, a ledger and a policy bundle, which this test is not about. The pipeline's
// own policy evaluation is covered by the engine and policy packages.
//
// Gated exactly like the other kernel tests: it needs root and a permission-capable kernel, so it runs on
// the rooted VM and skips everywhere else.

// requireExecPermIPC skips unless this is a root Linux host whose kernel supports fanotify permission mode.
func requireExecPermIPC(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exec-gate IPC kernel test needs root (CAP_SYS_ADMIN for fanotify permission mode)")
	}
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify permission mode unavailable: %v", err)
	}
	_ = unix.Close(fd)
}

// stubProcessor stands in for the engine: it returns DENY_EXEC for one path and ALLOW for anything else,
// through the real execguard mapping.
type stubProcessor struct{ denyPath string }

func (s stubProcessor) Process(_ context.Context, ev *corev1.Event) (*corev1.Decision, error) {
	action := corev1.Action_ACTION_ALLOW
	if ev.GetProcess().GetExecPath() == s.denyPath {
		action = corev1.Action_ACTION_DENY_EXEC
	}
	return &corev1.Decision{Action: action, Confidence: 0.99}, nil
}

func copyExecutable(t *testing.T, dst string) {
	t.Helper()
	src, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatalf("reading /bin/true: %v", err)
	}
	if err := os.WriteFile(dst, src, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestKernelExecDeniedViaIPC is the acceptance test: a verdict obtained over IPC refuses a REAL exec
// (EPERM, which is how FAN_DENY surfaces), and an allowed path still runs.
//
// MUTATION: bypass the IPC verdict (always answer allow) → the denied exec succeeds → this FAILS.
func TestKernelExecDeniedViaIPC(t *testing.T) {
	requireExecPermIPC(t)

	watched := t.TempDir()
	denied := filepath.Join(watched, "denied-binary")
	allowed := filepath.Join(watched, "allowed-binary")
	copyExecutable(t, denied)
	copyExecutable(t, allowed)

	// The engine side: a real execipc.Server whose verdict comes through the real execguard mapping.
	socket := socketPath(t, "v.sock")
	srv := &execipc.Server{
		Evaluate: execguard.ExecEvaluator{Decide: execguard.Decider(stubProcessor{denyPath: denied})}.Evaluate,
		Logf:     func(format string, a ...any) { t.Logf("server: "+format, a...) },
	}
	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	go func() { _ = srv.Listen(srvCtx, socket) }()
	waitForSocket(t, socket)

	// The privileged side: the real fanotify permission producer + watchdog + IPC client.
	mon, err := execmon.Open([]string{watched})
	if err != nil {
		t.Fatalf("opening the exec-permission monitor: %v", err)
	}
	defer mon.Close()

	client := execipc.NewClient(socket)
	client.Timeout = 2 * time.Second // generous: a VM under load must not fail open and mask the result
	client.CacheTTL = 0              // every exec must consult the pipeline, so the test measures the real path
	client.Logf = func(format string, a ...any) { t.Logf("client: "+format, a...) }
	defer client.Close()

	var failOpens int
	wd := &watchdog.Watchdog{
		SelfPID:   int32(os.Getpid()),
		Budget:    5 * time.Second,
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: client,
		Audit: func(_ context.Context, e watchdog.PermissionEvent, sev watchdog.Severity, reason string) error {
			failOpens++
			t.Logf("FAIL-OPEN pid=%d path=%q severity=%d reason=%q", e.PID, e.Path, int(sev), reason)
			return nil
		},
	}

	monCtx, monCancel := context.WithCancel(context.Background())
	defer monCancel()
	go func() { _ = mon.Run(monCtx, wd) }()
	time.Sleep(200 * time.Millisecond) // let the mark take effect

	// The denied binary must be REFUSED by the kernel.
	err = exec.CommandContext(context.Background(), denied).Run()
	if err == nil {
		t.Fatalf("%s executed successfully — the IPC verdict did not reach the kernel", denied)
	}
	// fanotify's FAN_DENY surfaces to the execing process as EPERM, not EACCES — worth pinning, because
	// the first version of this test asserted EACCES and failed against a correct implementation.
	if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("%s failed with %v, want a permission error (EPERM from FAN_DENY)", denied, err)
	}
	t.Logf("denied exec refused as expected: %v", err)

	// The allowed binary must still run — otherwise "denies things" would be indistinguishable from
	// "breaks the host".
	if err := exec.CommandContext(context.Background(), allowed).Run(); err != nil {
		t.Fatalf("%s was refused (%v) — an allowing verdict must let the exec through", allowed, err)
	}

	if failOpens != 0 {
		t.Errorf("%d fail-opens occurred; the verdicts above may not have come from the pipeline", failOpens)
	}
}

// intentPolicyRego is a REAL OPA policy that refuses an exec for a CONTAINed subject and allows otherwise.
// It reads the intent as CONTEXT — the control plane published data, this policy decided what it means.
const intentPolicyRego = `package openshield
import rego.v1
contained if { input.context.has_response_intent; input.context.response_intent == "INTENT_VERB_CONTAIN" }
decision := {"action":"DENY_EXEC","reason":"entity is contained","confidence":0.99} if { contained }
decision := {"action":"ALLOW","reason":"not contained","confidence":0.9} if { not contained }`

// TestKernelExecDeniedByContainIntent is HIPS-3 increment 2b, end to end on a real kernel: a CONTAIN
// Response-Intent (SOAR-7) makes a contained entity's next exec kernel-REFUSED, and the same binary runs
// when the intent is absent.
//
// Everything is real: the fanotify permission producer, the watchdog, the execipc bridge, a REAL OPA policy
// evaluating the intent as typed context, and a real exec. Only the intent's ARRIVAL is injected (the
// signed-publication half is D252's, tested there) — this proves the ENACTMENT half the ticket is about.
//
// MUTATION: stop resolving the intent into Context → the policy sees no containment → the exec is ALLOWED
// → this FAILS.
func TestKernelExecDeniedByContainIntent(t *testing.T) {
	requireExecPermIPC(t)

	watched := t.TempDir()
	target := filepath.Join(watched, "contained-binary")
	copyExecutable(t, target)

	const subject = "sub_contained_entity"
	const containIntentID = "INTENT_VERB_CONTAIN:sub_contained_entity:1"
	var contained bool // flipped between the two halves of the test

	pol, err := policy.New(context.Background(), "intent-exec", "1", intentPolicyRego)
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(passThroughWorker{}, pol, noopLedger{}, nil, 5*time.Second)
	eng.SetIntentResolver(func(s string) (corev1.IntentVerb, string, bool) {
		if s == subject && contained {
			return corev1.IntentVerb_INTENT_VERB_CONTAIN, containIntentID, true
		}
		return corev1.IntentVerb_INTENT_VERB_UNSPECIFIED, "", false
	})

	socket := socketPath(t, "v.sock")
	srv := &execipc.Server{
		Evaluate: execguard.ExecEvaluator{Decide: execguard.Decider(subjectStamper{eng: eng, subject: subject})}.Evaluate,
		Logf:     func(f string, a ...any) { t.Logf("server: "+f, a...) },
	}
	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	go func() { _ = srv.Listen(sctx, socket) }()
	waitForSocket(t, socket)

	mon, err := execmon.Open([]string{watched})
	if err != nil {
		t.Fatalf("opening the exec-permission monitor: %v", err)
	}
	defer mon.Close()
	client := execipc.NewClient(socket)
	client.Timeout = 3 * time.Second
	client.CacheTTL = 0
	defer client.Close()

	wd := &watchdog.Watchdog{
		SelfPID: int32(os.Getpid()), Budget: 6 * time.Second,
		Responder: watchdog.FanotifyResponder{NotifyFD: mon.NotifyFD()},
		Evaluator: client,
		Audit: func(_ context.Context, e watchdog.PermissionEvent, sev watchdog.Severity, reason string) error {
			t.Logf("FAIL-OPEN pid=%d path=%q severity=%d reason=%q", e.PID, e.Path, int(sev), reason)
			return nil
		},
	}
	mctx, mcancel := context.WithCancel(context.Background())
	defer mcancel()
	go func() { _ = mon.Run(mctx, wd) }()
	time.Sleep(200 * time.Millisecond)

	// No intent in effect: the binary runs.
	if err := exec.CommandContext(context.Background(), target).Run(); err != nil {
		t.Fatalf("with NO containment the exec was refused (%v) — the gate must not block by default", err)
	}

	// A CONTAIN intent arrives for this entity.
	contained = true
	err = exec.CommandContext(context.Background(), target).Run()
	if err == nil {
		t.Fatal("a CONTAINed entity's exec SUCCEEDED — the intent did not reach the kernel decision")
	}
	if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("contained exec failed with %v, want a permission error (EPERM from FAN_DENY)", err)
	}
	t.Logf("CONTAIN intent refused the exec as expected: %v", err)

	// And lifting the containment restores execution — a containment that could not be lifted would be a
	// permanent quarantine.
	contained = false
	if err := exec.CommandContext(context.Background(), target).Run(); err != nil {
		t.Fatalf("after the containment was lifted the exec was still refused (%v)", err)
	}
}

// subjectStamper gives the exec event the pseudonymous subject the intent is keyed by. In production the
// engine stamps the canonical subject (XDR-3); here it is explicit so the test states what it depends on.
type subjectStamper struct {
	eng     *engine.Engine
	subject string
}

func (s subjectStamper) Process(ctx context.Context, ev *corev1.Event) (*corev1.Decision, error) {
	ev.Subject = &corev1.Subject{PseudonymousId: s.subject}
	return s.eng.Process(ctx, ev)
}

// passThroughWorker classifies nothing: an exec event carries no content, and this test is about the
// intent reaching policy, not about detection.
type passThroughWorker struct{}

func (passThroughWorker) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	return &corev1.ClassifyResponse{RequestId: req.GetRequestId(), EventId: req.GetEventId()}, nil
}

type noopLedger struct{}

func (noopLedger) Append(context.Context, *core.Entry) error { return nil }
func (noopLedger) Close() error                              { return nil }
func (noopLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{}, nil
}
