package nats

import (
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// THE DEFAULT RECONNECT POLICY MAKES A LONG OUTAGE PERMANENT, and every long-lived process in this
// product was using it.
//
// nats.go defaults to MaxReconnects=60 with ReconnectWait=2s. That is a budget of roughly TWO MINUTES,
// after which the client closes the connection for good. The process stays alive and never publishes or
// receives again. Measured end to end: a 4-second broker outage recovers fully (2 -> 120 rows stored); a
// 150-second one never recovers, and the row count is still 2 thirty seconds after the broker is back on
// the same port with its state intact.
//
// Two minutes is not a long outage. A laptop closed over lunch, a switch reboot, a VPN drop, a broker
// upgrade — the normal case, not an edge case. And the consequences differ by process, all bad:
//
//   - The AGENT keeps producing into its disk spool (D40/D67) that it will now never drain. The spool
//     fills to OPENSHIELD_QUEUE_MAX and then starts DROPPING THE OLDEST records, so a bounded outage
//     silently becomes unbounded evidence loss — the exact failure the spool exists to prevent.
//   - The CONTROL PLANE stops consuming. That is not one endpoint, it is the whole fleet's ingest.
//   - The ENGINE and GATEWAY stop publishing decisions, so enforcement keeps happening and the record
//     of it does not.
//
// A daemon whose job is to keep reporting should retry forever. That is what MaxReconnects(-1) says, and
// it is the correct answer for every caller here — none of them is a short-lived command where giving up
// is the right behaviour. A one-shot CLI should NOT use these options.
//
// JITTER IS NOT DECORATION. When a broker returns, every agent in a fleet has been waiting on the same
// fixed 2s interval and reconnects in lockstep — a thundering herd against the process that just came
// back up, which is how a recovering broker gets knocked over again. The jitter spreads them.
//
// AND THE STATE CHANGES ARE LOGGED, because until now a disconnected agent said nothing about being
// disconnected: the only hint was a periodic "flush stopped after 0 (still unreachable?)" from the spool
// drain, which reads as a spool problem rather than a connectivity one. A gap must never be silent (D31).

const (
	// reconnectWait is the base delay between attempts. Short enough that a blip recovers promptly,
	// long enough that a down broker is not hammered by a whole fleet.
	reconnectWait = 2 * time.Second
	// reconnectJitter spreads a fleet's reconnect attempts so a broker coming back is not hit by all of
	// them at once. The TLS variant is larger because a handshake costs the broker more than a plain
	// reconnect does.
	reconnectJitter    = 1 * time.Second
	reconnectJitterTLS = 4 * time.Second

	// pingInterval/maxPingsOut decide HOW FAST A SILENTLY DEAD CONNECTION IS NOTICED, and the defaults
	// (2 minutes x 2) mean up to FOUR MINUTES.
	//
	// This only matters for the outage that does not close the socket. A stopped broker sends a RST and the
	// client knows immediately; an ENDPOINT whose own interface vanishes — a closed laptop, a dropped VPN, a
	// detached container — leaves a TCP connection that is dead and looks open. Until a ping times out the
	// client still reports connected, so it does not reconnect, and every attempt to drain the spool fails
	// with `nats: timeout` while the spool keeps growing.
	//
	// Measured in exactly that shape (a container removed from its network): the agent logged neither a
	// disconnect nor a reconnect for the whole partition, just `flush stopped after 0 (still unreachable?):
	// nats: timeout` over and over, and it was still doing so after the network came back. A broker-outage
	// test cannot find this, which is the empirical case for testing a real partition.
	//
	// 20s x 2 puts detection at ~40s. The cost is one PING per connection per 20s, which is nothing next to
	// a four-minute window in which an endpoint is neither delivering nor recovering.
	pingInterval = 20 * time.Second
	maxPingsOut  = 2
)

// ResilienceOptions returns the reconnect policy every LONG-LIVED OpenShield process should use: retry
// forever, with jitter, and say so.
//
// onEvent receives a human-readable, already-formatted line for each connection state change. It is a
// callback rather than a logger because the callers here log three different ways (slog in the engine,
// gateway and control plane; stderr in the agent), and a package this low should not pick for them. A nil
// callback is allowed and means "reconnect forever, quietly" — available, but note that it gives up the
// D31 half of this.
func ResilienceOptions(onEvent func(string)) []nats.Option {
	emit := func(string) {}
	if onEvent != nil {
		emit = onEvent
	}
	return []nats.Option{
		// -1 is infinite. THIS is the fix; everything else here is hygiene around it.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(reconnectWait),
		nats.ReconnectJitter(reconnectJitter, reconnectJitterTLS),
		// Detect a dead-but-open connection in ~40s instead of ~4 minutes. See the constants.
		nats.PingInterval(pingInterval),
		nats.MaxPingsOutstanding(maxPingsOut),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			// A NIL ERROR MEANS WE CLOSED IT, and this handler fires then too. Without the guard every
			// clean shutdown printed
			//
			//   broker connection lost (<nil>) — retrying forever; telemetry is being spooled, not sent
			//
			// which is false on all three counts: nothing was lost, nothing is being retried, and nothing
			// is being spooled. It showed up in the shutdown output of a passing test, which is the only
			// reason it was noticed — a misleading line in a log nobody reads on a green run is exactly
			// the kind of thing that later gets quoted in an incident review.
			if err == nil {
				return
			}
			// Reported at the moment it happens rather than inferred later from missing data.
			emit(fmt.Sprintf("broker connection lost (%v) — retrying forever; telemetry is being spooled, not sent", err))
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			emit(fmt.Sprintf("broker reconnected to %s — draining anything spooled during the outage", c.ConnectedUrl()))
		}),
		// NO ClosedHandler, and the omission is deliberate rather than forgotten.
		//
		// The tempting version logs "connection closed permanently, this process will never publish
		// again" as the loudest line in the file. But nats.go invokes ClosedHandler on an explicit
		// Close() as well, so that line would fire on EVERY CLEAN SHUTDOWN — and a maximum-severity
		// warning that appears on every normal exit is worse than no warning: it is the one an operator
		// learns to scroll past, and it would be there in the log of a machine that shut down correctly.
		//
		// The alarm it was meant to raise cannot happen anyway. With MaxReconnects(-1) the client never
		// gives up on its own, so a permanent close is only ever a deliberate Close(). The handler would
		// add no signal and cost the credibility of the log.
	}
}
