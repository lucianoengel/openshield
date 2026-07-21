package gateway_test

import (
	"context"
	"crypto/ed25519"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/flow"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
)

// A valid CPF (111.444.777-35) — the same fixture the endpoint skeleton uses.
const cpfBody = "name,cpf\nalice,111.444.777-35\n"

// --- fakes: no sockets, no Postgres, no real worker ---

type recLedger struct{ entries []*core.Entry }

func (l *recLedger) Append(_ context.Context, e *core.Entry) error {
	cp := *e
	l.entries = append(l.entries, &cp)
	return nil
}
func (l *recLedger) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return core.VerifyResult{Consistent: true}, nil
}
func (l *recLedger) Close() error { return nil }

// fakeWorker stands in for the sandboxed worker: it returns configured hits
// WITHOUT parsing, so assembly tests do not spawn a process. It also records the
// request so a test can assert the body was sent as inline content, never a path.
type fakeWorker struct {
	hits    []*corev1.DetectorHit
	lastReq *corev1.ClassifyRequest
}

func (f *fakeWorker) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	f.lastReq = req
	return &corev1.ClassifyResponse{RequestId: req.GetRequestId(), EventId: req.GetEventId(), Hits: f.hits}, nil
}

func cpfHit() []*corev1.DetectorHit {
	return []*corev1.DetectorHit{{DetectorType: corev1.DetectorType_DETECTOR_TYPE_CPF, Confidence: 0.95, Count: 2}}
}

// fakeTable stands in for the socket-backed flow table (N1.2b). It records which
// flow_id each verdict acted on, proving the target reached the table.
type fakeTable struct {
	blocked    []string
	redirected []string
}

func (t *fakeTable) Block(flowID string) error { t.blocked = append(t.blocked, flowID); return nil }
func (t *fakeTable) Redirect(flowID string) error {
	t.redirected = append(t.redirected, flowID)
	return nil
}

type stageFn struct {
	name string
	fn   func(context.Context, *core.State) (core.Outcome, error)
}

func (s stageFn) Name() string { return s.name }
func (s stageFn) Run(ctx context.Context, st *core.State) (core.Outcome, error) {
	return s.fn(ctx, st)
}

func deciding(action corev1.Action) core.Stage {
	return stageFn{"policy", func(_ context.Context, st *core.State) (core.Outcome, error) {
		return core.Decided(&corev1.Decision{
			DecisionId: "d", EventId: st.Event.GetEventId(), Action: action,
		}), nil
	}}
}

func req(flowID, body string) *gateway.Request {
	return &gateway.Request{
		FlowID: flowID, SrcIP: "10.0.0.5", SrcPort: 44321,
		DstIP: "93.184.216.34", DstPort: 443, Protocol: "tcp",
		Host: "upload.example.com", Method: "POST", Path: "/files",
		Direction: corev1.NetworkDirection_NETWORK_DIRECTION_EGRESS,
		Body:      []byte(body),
	}
}

// The network walking skeleton: a request whose BODY carries a CPF is classified
// IN THE REAL SANDBOXED WORKER (built + started here), then flows the REAL policy →
// decision → audit ledger, landing an ALERT — no sockets, no Postgres. This proves
// D72: the body is parsed in the worker, not in the gateway process.
func TestGatewayWalkingSkeletonUsesTheWorker(t *testing.T) {
	ctx := context.Background()
	bin := filepath.Join(t.TempDir(), "openshield-worker")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/openshield-worker").CombinedOutput(); err != nil {
		t.Fatalf("building worker: %v\n%s", err, out)
	}
	w, err := privileged.StartWorker(ctx, bin)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	pol, err := policy.NewDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	led := &recLedger{}
	g := gateway.NewFromWorker(w, pol, led, nil, 10*time.Second)

	dec, err := g.Process(ctx, req("flow-1", cpfBody))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if dec.GetAction() != corev1.Action_ACTION_ALERT {
		t.Fatalf("decision = %v, want ALERT for a request body with a CPF (classified in the worker)", dec.GetAction())
	}
	if len(led.entries) != 1 || led.entries[0].Decision.GetAction() != corev1.Action_ACTION_ALERT {
		t.Fatalf("expected one audited ALERT, got %d entries", len(led.entries))
	}
}

// The gateway sends the body as INLINE CONTENT to the worker, never a path — the
// gateway holds the bytes and hands them over; it does not ask the worker to open
// a file (D72).
func TestGatewayClassifiesBodyAsInlineContent(t *testing.T) {
	fw := &fakeWorker{hits: cpfHit()}
	g := gateway.New(fw, deciding(corev1.Action_ACTION_ALERT), &recLedger{}, nil, time.Second)

	if _, err := g.Process(context.Background(), req("flow-1", cpfBody)); err != nil {
		t.Fatal(err)
	}
	if fw.lastReq == nil {
		t.Fatal("the worker was never called")
	}
	if _, ok := fw.lastReq.GetSubject().(*corev1.ClassifyRequest_Content); !ok {
		t.Errorf("gateway sent subject %T, want inline Content — it must not ask the worker to open a path", fw.lastReq.GetSubject())
	}
	if string(fw.lastReq.GetContent()) != cpfBody {
		t.Errorf("worker received %q, want the request body", fw.lastReq.GetContent())
	}
}

// No body content crosses out of the classify step: the classification the policy
// sees carries type + count with EMPTY matched text (D10/D29).
func TestNoBodyContentCrossesTheBoundary(t *testing.T) {
	var captured *corev1.LocalClassification
	capture := stageFn{"policy", func(_ context.Context, st *core.State) (core.Outcome, error) {
		captured = st.Classification
		return core.Decided(&corev1.Decision{
			DecisionId: "d", EventId: st.Event.GetEventId(), Action: corev1.Action_ACTION_ALERT,
		}), nil
	}}
	g := gateway.New(&fakeWorker{hits: cpfHit()}, capture, &recLedger{}, nil, time.Second)

	if _, err := g.Process(context.Background(), req("flow-1", cpfBody)); err != nil {
		t.Fatal(err)
	}
	if captured == nil || len(captured.GetMatches()) != 2 {
		t.Fatalf("expected 2 matches from count=2, got %v", captured)
	}
	for _, m := range captured.GetMatches() {
		if m.GetMatchedText() != "" {
			t.Errorf("a match carried body content %q — no content may leave the gateway (D10/D29)", m.GetMatchedText())
		}
		if m.GetDetectorType() != corev1.DetectorType_DETECTOR_TYPE_CPF {
			t.Errorf("match type = %v, want CPF", m.GetDetectorType())
		}
	}
}

// A worker error terminates as a failure, not a clean "nothing found" result (D17).
func TestWorkerErrorIsAFailure(t *testing.T) {
	g := gateway.New(erroringWorker{}, stageFn{"policy", func(context.Context, *core.State) (core.Outcome, error) {
		t.Error("policy ran despite a classify failure")
		return core.Continue(), nil
	}}, &recLedger{}, nil, time.Second)

	if _, err := g.Process(context.Background(), req("flow-1", cpfBody)); err == nil {
		t.Fatal("a worker error produced no error — a failed parse must not read as a clean result (D17)")
	}
}

type erroringWorker struct{}

func (erroringWorker) Classify(_ context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error) {
	return &corev1.ClassifyResponse{RequestId: req.GetRequestId(), Error: "worker: classify: boom"}, nil
}

// A BLOCK verdict routes to a registered flow enforcer, which acts on the flow_id
// via the flow table; a REDIRECT verdict routes to the redirect path.
func TestFlowEnforcerReceivesFlowID(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		action                      corev1.Action
		wantBlocked, wantRedirected []string
	}{
		{"block", corev1.Action_ACTION_BLOCK, []string{"flow-block"}, nil},
		{"redirect", corev1.Action_ACTION_REDIRECT, nil, []string{"flow-redir"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tbl := &fakeTable{}
			g := gateway.New(&fakeWorker{hits: cpfHit()}, deciding(tc.action), &recLedger{}, nil, time.Second)
			g.Enforcers = []core.Enforcer{flow.New(tbl)}

			flowID := "flow-block"
			if tc.action == corev1.Action_ACTION_REDIRECT {
				flowID = "flow-redir"
			}
			if _, err := g.Process(context.Background(), req(flowID, cpfBody)); err != nil {
				t.Fatal(err)
			}
			if got := len(tbl.blocked) + len(tbl.redirected); got != 1 {
				t.Fatalf("flow table touched %d times, want exactly 1", got)
			}
			if tc.wantBlocked != nil && (len(tbl.blocked) != 1 || tbl.blocked[0] != tc.wantBlocked[0]) {
				t.Errorf("blocked = %v, want %v", tbl.blocked, tc.wantBlocked)
			}
			if tc.wantRedirected != nil && (len(tbl.redirected) != 1 || tbl.redirected[0] != tc.wantRedirected[0]) {
				t.Errorf("redirected = %v, want %v", tbl.redirected, tc.wantRedirected)
			}
		})
	}
}

// Observe-only default (D1): with no enforcer registered, a BLOCK decision is
// recorded but the flow table is never touched.
func TestObserveOnlyDefault(t *testing.T) {
	tbl := &fakeTable{}
	led := &recLedger{}
	g := gateway.New(&fakeWorker{hits: cpfHit()}, deciding(corev1.Action_ACTION_BLOCK), led, nil, time.Second)
	// No g.Enforcers — the flow table exists but is not wired.

	dec, err := g.Process(context.Background(), req("flow-1", cpfBody))
	if err != nil {
		t.Fatal(err)
	}
	if dec.GetAction() != corev1.Action_ACTION_BLOCK {
		t.Fatalf("decision = %v, want BLOCK", dec.GetAction())
	}
	if len(tbl.blocked)+len(tbl.redirected) != 0 {
		t.Errorf("flow table was touched with no enforcer registered — observe-only violated (D1)")
	}
	if len(led.entries) != 1 {
		t.Errorf("decision not recorded: %d entries, want 1", len(led.entries))
	}
}
