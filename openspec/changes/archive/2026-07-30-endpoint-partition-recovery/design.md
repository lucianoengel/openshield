# Design

## Why a container, and why nothing smaller would do

The property is "the endpoint's own interface goes away". Simulating that needs a real network namespace.
Everything cheaper changes something else instead:

- Stopping the broker closes the socket. That is the outage already tested, and it is the one that hides
  this bug.
- Blocking with firewall rules needs privilege on the host and would affect the host's own networking.
- Killing the agent tests restart, not partition.

`podman network disconnect` removes the interface from a running container and `connect` puts one back —
rootless, no privilege, and the rejoin gets a **different IP**, which is the realistic case for free.

## Two obstacles, and what they say about the harness

**The stack's broker cannot join a bridge network.** The harness starts NATS in the default rootless
network mode, and `podman network connect` refuses it outright: `"slirp4netns" is not supported: invalid
network mode`. So this scenario brings up its own broker on the bridge, published to a host port so the
control plane — a host process — still reaches it at 127.0.0.1 while the agent reaches it **by name** over
the bridge. Using the name is deliberate: it puts DNS inside the partition rather than beside it.

**The agent must not need to enrol from inside the container.** The enrolment endpoint binds 127.0.0.1, and
binding it to 0.0.0.0 would widen a listener on the developer's machine for the duration of a test run. So
the agent enrols as a host process, persists its identity (D318), and the container starts with that
identity and **no token** — which is the stronger starting point anyway, since an agent that needs a token
to come back has been re-provisioned rather than restarted.

The binary is built with `CGO_ENABLED=0`; the harness's is dynamically linked against the host libc, which
a minimal image does not have.

## The finding this test exists for

The agent's own log is the whole diagnosis, and it is an absence rather than an error:

```
fleet-agent: flush stopped after 0 (still unreachable?): nats: timeout      (x N)
```

No disconnect line. No reconnect line. The client did not think anything was wrong — so `IsConnected()`
stayed true, no reconnect was attempted, and each JetStream publish sat waiting for an ack that could not
arrive. Records still spooled, but via the send-failure path (`an outage mid-send must not lose the
payload`), and once `spool.Len() > 0` everything spools. So the SYMPTOM looked like a working spool and a
broken drain.

The cause is the keepalive budget: `PingInterval=2m` × `MaxPingsOutstanding=2`. Nothing else can notice a
connection that is dead and silent.

**D368's infinite reconnect cannot help.** You cannot reconnect a connection you do not know is broken.
Two fixes that both look like "make the client resilient", where the first is invisible without the second.

## The clean-shutdown log line, found in a passing test

`DisconnectErrHandler` fires on a deliberate `Close()` as well, with a **nil** error. So every clean
shutdown printed:

```
broker connection lost (<nil>) — retrying forever; telemetry is being spooled, not sent
```

False on all three counts. It surfaced in the captured shutdown output of a test that PASSED, which is the
only reason it was seen — a misleading line on a green run is exactly the kind that later gets quoted in an
incident review. `err == nil` is the discriminator.

This is the second time in this area that the right answer was "do not log that": the omitted
`ClosedHandler` (D368) fires on clean shutdown for the same reason.

## Mutation

`PingInterval` back to the 2-minute default. The scenario fails with 76 records still held after 208s,
against a pass in 66s. So the constant is load-bearing and the test measures the property rather than the
weather.
