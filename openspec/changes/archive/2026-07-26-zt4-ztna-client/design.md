## Context

`internal/gateway.AccessProxy` already authorizes with device cert + OIDC user + attestation + posture and
routes through an allow-list catalog (D86–D88). What is missing is the endpoint side: today an application
must be pointed at the gateway by hand, and nothing on the device presents the device's identity.

## Goals / Non-Goals

**Goals:** a local broker that applications can use unmodified (HTTP proxy interface); device-cert mTLS to
the access proxy; honest refusal reporting; refuse to start without an identity.

**Non-Goals:** enforcing that traffic cannot bypass the broker (routing/firewall — a separate ticket over
the existing NIPS-1 plane); arbitrary TCP via CONNECT/SOCKS; split DNS; certificate enrollment.

## Decisions

### D-1: An HTTP proxy interface, not a TUN device

Applications already speak `HTTP_PROXY`, and a proxy needs no privilege, no kernel interface and no
platform-specific networking. A TUN interface would capture all traffic (closer to commercial ZTNA) at the
cost of root, per-platform code, and a much larger failure surface — deferred deliberately, and named in the
proposal so nobody reads "ZTNA client" as "network jail".

### D-2: The device certificate is the client's TLS identity

The tunnel to the broker is mTLS with the enrolled device certificate; the user's bearer token rides in the
request. That is exactly the dual credential the access proxy already requires (ZT-3), so the endpoint
authorizes with *both* facts and the server side needs no change.

### D-3: Never fall back

A refusal is returned to the application as an error. No unauthenticated retry, no direct connection. A
client that "helpfully" falls back turns a Zero-Trust denial into an ordinary network request, which is the
worst possible outcome and the exact behavior the test pins.

## Risks / Trade-offs

- **Bypassable by design at this stage** (D-1). Stated plainly rather than implied away.
- **The proxy is a local listener**: it must bind loopback only, or it becomes a network-reachable relay
  that anyone on the LAN could use with the device's identity.
- **Token handling**: the user credential lives in the client's memory; it is attached per request and never
  logged.

## Migration Plan

Additive and opt-in: nothing changes until the client is run and applications are pointed at it.
