package controlplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// THE TELEMETRY STREAM WAS CREATED ONCE, AT STARTUP, AND NEVER AGAIN (PLAT-10).
//
// `natsx.EnsureTelemetryStream` was called from exactly two places — this package's Run and the producers'
// UseJetStream — both during process start. So a broker that came back WITHOUT the stream stayed without
// it, and the whole fleet's ingest stopped permanently:
//
//   - every agent's publish failed with `no response from stream`, forever;
//   - this server's durable push consumer had been deleted along with the stream, so it received nothing
//     and said NOTHING AT ALL;
//   - every agent's spool grew to OPENSHIELD_QUEUE_MAX and began dropping the OLDEST records.
//
// Reproduced end to end (`Stack.RestoreBrokerEmpty`): rows frozen for 30s+ while an agent published every
// 500ms. A broker restarted WITH its store recovers fully (2 -> 120 rows), which is what makes this a
// specific defect rather than a general outage story. And it is ordinary ops: `podman rm` and recreate the
// broker, or an orchestrator rescheduling it onto fresh storage.
//
// WHY A POLL AND NOT A RECONNECT HANDLER. A reconnect handler was the obvious hook and it is not enough: a
// stream can be deleted while the connection stays perfectly healthy — an operator with `nats stream rm`, a
// retention policy misconfigured, a cluster losing the asset without dropping TCP. No disconnect happens,
// so no handler fires. Checking the consumer on a timer catches that case and the reconnect case with one
// mechanism, and it cannot miss an edge it was not told about.
//
// WHY IT REPAIRS RATHER THAN ONLY WARNING. Warning alone would satisfy D31 and leave the fleet down until
// somebody restarted the server. The repair is well-defined — the stream config is a constant and the
// consumer is durable by name — so there is nothing to guess.
//
// WHAT IS DELIBERATELY NOT CLAIMED: messages published into the gap are gone. They were REFUSED by a broker
// with no stream, not buffered by it. Recovery depends on the producers having spooled them (D40/D67) and
// re-sending, which is what the agent's queue is for. This heals the CHANNEL, not the contents.

const (
	// ingestHealInterval is how often the durable consumer is checked. Short enough that a broker replaced
	// during a deploy costs seconds of ingest rather than however long until someone notices; long enough
	// to be free (one ConsumerInfo round trip).
	ingestHealInterval = 15 * time.Second
)

// IngestRepairs counts how many times the telemetry consumer had to be rebuilt. Exported and counted
// because a repair is evidence of a broker having lost its state, which an operator wants to know about
// even though the product recovered by itself — a self-healing system that heals silently teaches nobody
// that its broker is being replaced under it.
type ingestHealth struct {
	repairs atomic.Int64
	failed  atomic.Int64
}

// healIngest keeps the durable telemetry consumer alive for as long as ctx lives.
//
// resubscribe is injected so the caller owns how a subscription is built and stored; this function owns only
// the decision that one is needed.
func (s *Server) healIngest(ctx context.Context, conn *nats.Conn, resubscribe func(nats.JetStreamContext) error) {
	t := time.NewTicker(ingestHealInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Nothing to conclude while disconnected: the resilience options are reconnecting, and a
			// ConsumerInfo attempted now would fail for a reason that says nothing about the stream.
			if !conn.IsConnected() {
				continue
			}
			js, err := conn.JetStream()
			if err != nil {
				continue
			}
			if _, err := js.ConsumerInfo(natsx.TelemetryStream, natsx.TelemetryDurable); err == nil {
				continue // healthy, which is the overwhelmingly common case
			} else if !errors.Is(err, nats.ErrConsumerNotFound) && !errors.Is(err, nats.ErrStreamNotFound) {
				// SOME OTHER ERROR IS NOT A REASON TO REBUILD. A timeout or a transient cluster error would
				// otherwise tear down and recreate a working consumer on every blip, which is a worse
				// failure than the one being fixed — the repair must be narrower than "something is off".
				continue
			}

			// Ingest has stopped. Say so BEFORE trying to fix it, so the log shows what happened even if
			// the repair then fails.
			fmt.Fprintf(os.Stderr, "openshield-server: TELEMETRY INGEST IS DOWN — the durable consumer %q on "+
				"stream %q is gone, which means the broker came back without its JetStream state. No agent "+
				"telemetry is being stored. Rebuilding.\n", natsx.TelemetryDurable, natsx.TelemetryStream)

			if err := natsx.EnsureTelemetryStream(js); err != nil {
				s.ingest.failed.Add(1)
				fmt.Fprintf(os.Stderr, "openshield-server: could not recreate the telemetry stream: %v — "+
					"ingest stays down and will be retried in %s\n", err, ingestHealInterval)
				continue
			}
			if err := resubscribe(js); err != nil {
				s.ingest.failed.Add(1)
				fmt.Fprintf(os.Stderr, "openshield-server: recreated the telemetry stream but could not "+
					"resubscribe: %v — ingest stays down and will be retried in %s\n", err, ingestHealInterval)
				continue
			}
			s.ingest.repairs.Add(1)
			fmt.Fprintf(os.Stderr, "openshield-server: telemetry ingest RESTORED (repair #%d). Records "+
				"published while the stream was missing were refused by the broker, not buffered — they "+
				"return only as producers drain their offline spools.\n", s.ingest.repairs.Load())
		}
	}
}

// IngestRepairs reports how many times the telemetry consumer was rebuilt.
func (s *Server) IngestRepairs() int64 { return s.ingest.repairs.Load() }

// IngestRepairFailures reports how many repair attempts failed. Non-zero means ingest was down and stayed
// down through at least one attempt.
func (s *Server) IngestRepairFailures() int64 { return s.ingest.failed.Load() }
