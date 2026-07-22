package prefilter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/watchdog"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/safeio"
)

// classifier is the subset of the worker the decider needs — the SAME interface the
// engine and gateway hold (*privileged.Worker satisfies it). Content is parsed IN the
// worker (D72); this package never links a parser.
type classifier interface {
	Classify(ctx context.Context, req *corev1.ClassifyRequest) (*corev1.ClassifyResponse, error)
}

// Decider is the concrete PartialDecider: it produces a Decision from a CHEAP, BOUNDED
// classification of a permission event's target. It reads only a size-limited PREFIX of
// the file, hands those bytes to the sandboxed worker to parse (D72 — the content stays
// in the worker), then runs the SAME OPA policy the async engine runs, and returns the
// Decision WITHOUT writing an audit row (the async tier owns the durable record). It is
// the synchronous tier's engine, minus the parse surface and minus the ledger.
//
// The prefix read is bounded twice: the reader stops at maxBytes, and the worker's own
// MaxBytes ceiling caps the parse — so a huge file cannot make the permission window
// unbounded. Reading the prefix is a raw byte read, not a parse: the decider (which runs
// in the unprivileged engine, not the privileged agent) may hold bytes; only the worker
// parses them (D13).
type Decider struct {
	c        classifier
	policy   core.Stage
	maxBytes uint64
	open     func(path string) (io.ReadCloser, error) // injectable for tests
	deadline time.Duration
	logger   *slog.Logger
}

// NewDecider builds the partial decider. maxBytes bounds the synchronous prefix read
// (raised to a default if ≤ 0); policy is the SAME default-deny/observe policy the async
// engine uses; deadline bounds the classify+policy dispatch (the watchdog's budget is the
// outer bound, but a tight inner deadline keeps a slow worker from eating the window).
func NewDecider(c classifier, policy core.Stage, maxBytes uint64, deadline time.Duration, logger *slog.Logger) *Decider {
	if maxBytes == 0 {
		maxBytes = DefaultPrefixBytes
	}
	if deadline <= 0 {
		deadline = DefaultPartialDeadline
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Decider{c: c, policy: policy, maxBytes: maxBytes, open: openFile, deadline: deadline, logger: logger}
}

// DefaultPrefixBytes is the synchronous prefix ceiling — enough to catch a
// front-loaded secret (a leading PII block, a file header) without reading a whole file
// in the permission window.
const DefaultPrefixBytes = 64 * 1024

// DefaultPartialDeadline bounds the classify+policy dispatch inside the permission window.
const DefaultPartialDeadline = 50 * time.Millisecond

// openFile opens the prefix source with O_NOFOLLOW + regular-file-only (SEC-7): the inline
// prefilter reads a permission-window target, so it must apply the SAME TOCTOU discipline as
// the enforcers (D65) — an attacker who swaps the flagged path for a symlink must not
// redirect the read. safeio returns a *os.File (an io.ReadCloser) so the prefix read stays
// bounded (only maxBytes is read), not the whole file.
func openFile(path string) (io.ReadCloser, error) { return safeio.OpenRegularNoFollow(path) }

// DecidePartial reads a bounded prefix of the event's target, classifies it in the
// worker, runs the policy, and returns the Decision. A read/parse failure is an error,
// never a silent clean verdict (D17) — the prefilter turns that error into a fail-open,
// but the decider must SURFACE it.
func (d *Decider) DecidePartial(ctx context.Context, e watchdog.PermissionEvent) (*corev1.Decision, error) {
	if e.Path == "" {
		return nil, fmt.Errorf("prefilter: permission event has no path to classify")
	}
	rc, err := d.open(e.Path)
	if err != nil {
		return nil, fmt.Errorf("prefilter: opening %s: %w", e.Path, err)
	}
	defer rc.Close()

	prefix, err := io.ReadAll(io.LimitReader(rc, int64(d.maxBytes)))
	if err != nil {
		return nil, fmt.Errorf("prefilter: reading prefix of %s: %w", e.Path, err)
	}

	ev := &corev1.Event{
		EventId:     "perm-" + e.Path,
		ConnectorId: "prefilter",
		Kind:        corev1.EventKind_EVENT_KIND_FILE_OPENED,
		Target: &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{ResolvedPath: e.Path},
		}},
	}

	var reg core.Registry
	reg.Register(prefixClassifyStage{c: d.c, body: prefix, maxBytes: d.maxBytes})
	reg.Register(d.policy)
	disp := core.NewDispatcher(&reg, d.deadline)
	// NO OnOutcome: the synchronous tier does not write the ledger — the async engine
	// owns the durable audit row (D16). The decision is returned to the prefilter only.
	return disp.Dispatch(ctx, ev)
}

// prefixClassifyStage hands the bounded prefix to the worker and puts a content-free
// classification on State — the permission-window analogue of the engine/gateway
// classify stage. The prefix is HELD here but PARSED in the worker (D72); matched text
// never crosses the IPC (D10/D29).
type prefixClassifyStage struct {
	c        classifier
	body     []byte
	maxBytes uint64
}

func (prefixClassifyStage) Name() string { return "prefilter-classify" }

func (s prefixClassifyStage) Run(ctx context.Context, st *core.State) (core.Outcome, error) {
	resp, err := s.c.Classify(ctx, &corev1.ClassifyRequest{
		RequestId: st.Event.GetEventId(),
		EventId:   st.Event.GetEventId(),
		Subject:   &corev1.ClassifyRequest_Content{Content: s.body},
		MaxBytes:  s.maxBytes,
	})
	if err != nil {
		return core.Outcome{}, fmt.Errorf("prefilter-classify: worker: %w", err)
	}
	if resp.GetError() != "" {
		return core.Outcome{}, fmt.Errorf("prefilter-classify: worker reported: %s", resp.GetError())
	}
	lc := &corev1.LocalClassification{EventId: st.Event.GetEventId()}
	for _, h := range resp.GetHits() {
		for i := uint32(0); i < h.GetCount(); i++ {
			lc.Matches = append(lc.Matches, &corev1.LocalMatch{
				DetectorType: h.GetDetectorType(),
				Confidence:   h.GetConfidence(),
				// MatchedText deliberately empty — no content crossed the IPC.
			})
		}
	}
	st.Classification = lc
	return core.Continue(), nil
}

var _ PartialDecider = (*Decider)(nil)
