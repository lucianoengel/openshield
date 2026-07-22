# Design — NIPS-3 DNS source wiring

## The source IP was a real gap, not a cosmetic one

The listener read datagrams with `ReadFromUDP`, which returns the sender's address, and threw
it away. For a metadata-only connector that seemed harmless — until you produce an Event from
it. `ToEvent` populates `NetworkSubject.SrcIp`, and a network policy's whole job is to decide on
a flow: who, to where, over what. Dropping the source made every DNS Event anonymous. So the
sink signature changes to `func(srcIP string, q Query)`. This ripples only to the listener test
(the sole caller) and is a strict improvement.

## A testable helper, not logic buried in main()

`main()` is not unit-testable, and the wiring — mint a flow id, thread the source IP, produce
the Event, send it without blocking shutdown — is exactly the part worth testing. So it lives in
`dnsListener(ctx, addr, events, log) (*dns.Listener, error)`, which builds the listener with the
event-producing sink and returns it; `main()` runs `Serve` in a `wg`-tracked goroutine. The test
calls `dnsListener`, sends a real UDP query, and asserts a `NetworkSubject` Event lands on the
channel with the queried name in `SniHost` and the loopback source in `SrcIp` — the end-to-end
proof that listener → producer → pipeline is connected.

## Shutdown ordering

The event channel is closed by `go func(){ wg.Wait(); close(events) }()` once all producers
finish. The DNS `Serve` goroutine is added to the same `wg`, so the channel is never closed
while the DNS source might still send — a send on a closed channel would panic. Within the sink,
the send races `ctx.Done()`, so a query arriving during shutdown is abandoned rather than
blocking the listener's receive loop against a drained consumer.

## Mutation proof

The load-bearing wiring is "the parsed query becomes an Event carrying its name and source".
Dropping the source IP in the sink (`ToEvent(flowID, "", q)`) makes the test's `SrcIp` assertion
fail; the `SniHost` assertion guards that `ToEvent` is called with the real query rather than a
blank Event. Together they pin the whole sink→producer→channel path.
