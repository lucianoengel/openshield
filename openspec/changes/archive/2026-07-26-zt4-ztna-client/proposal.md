## Why

OpenShield's Zero-Trust access path is a **server-side reverse proxy**: an application must already know to
send its request to the gateway, and the gateway authorizes it with device certificate, OIDC user,
attestation and posture. That is half of ZTNA.

The other half — the half every commercial ZTNA (Zscaler ZPA, Cloudflare Access, Tailscale) actually ships
— is an **agent on the endpoint that brokers the connection**. The application talks to the local agent,
the agent presents the device's identity to the broker, and the internal service is reached only through
that path. Without it, "Zero-Trust access" requires every application to be reconfigured, and the endpoint's
own identity is not what authorizes the connection.

## What Changes

- **An agent-brokered access client** (`internal/ztna` + a client mode): a local HTTP proxy on the endpoint
  that applications point at. For each request it opens a mutually-authenticated connection to the access
  proxy using the **device certificate** and attaches the user's bearer token, so the connection is
  authorized by device identity + user identity + attestation + posture — the existing dual-credential
  path, now driven from the endpoint.
- **The client refuses to run without a device identity**, rather than silently forwarding unauthenticated.
- **Refusals are surfaced usefully**: an unattested or unauthorized device gets a clear local error naming
  the reason the broker gave, instead of an opaque connection failure.

## Capabilities

### New Capabilities

- `ztna-client`: the endpoint-side broker — local listener, device-authenticated tunnel to the access
  proxy, and honest reporting of refusal reasons.

## Impact

- **Code:** new `internal/ztna`, a client mode in the agent binary set, no server-side change (the access
  proxy already implements the authorization it needs).
- **Decisions:** builds on **D86/D87/D88** (verified identity, fail-closed authorization, catalog
  allow-list), **ZT-1** (attestation) and **ZT-3** (dual credential). It establishes no new decision.

### What this change does NOT claim or cover

- **It does not, by itself, prevent an application from bypassing it.** A local proxy brokers traffic that
  is sent to it; an application with a direct route to the internal network can still take it. Real ZTNA
  enforces the path with routing and firewall rules — OpenShield already has the mechanism for that
  (the NIPS-1 transparent inline plane), but wiring it to the ZTNA client is a separate ticket, and until
  then this is an access broker, not a network jail. Claiming otherwise would be the overclaim this project
  exists to avoid.
- It brokers **HTTP(S) through an HTTP proxy interface**. Arbitrary TCP (SSH, RDP, databases) needs a
  CONNECT/SOCKS path and is deferred.
- It does **not** do split-DNS or private-DNS resolution of internal names.
- It does **not** manage certificate enrollment; it uses the identity the agent already enrolled (ZT-1).
- Refusals are only as informative as the broker's response allows; it does not infer a reason the server
  did not give.
