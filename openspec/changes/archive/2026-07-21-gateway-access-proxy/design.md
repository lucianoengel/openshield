## Context

The gateway today is a FORWARD/egress proxy (D73–D78): a client's outbound traffic is
classified and a verdict applied, failing OPEN on error (D73/D17 — availability of
monitored traffic). D85 added the identity context and D86 the client-cert producer.
An ACCESS proxy is the reverse: a client connects TO the gateway to reach an INTERNAL
service, and the gateway decides whether to admit them by IDENTITY — a different
verdict shape and a different failure direction.

## Goals / Non-Goals

**Goals:** authenticate a client cert, resolve identity into the pipeline, authorize
per request on it, reverse-proxy allowed requests to an internal service, fail closed.

**Non-Goals:** the service catalog + per-service policy + binary wiring (A.4); OIDC;
the posture producer; the risk loop.

## Decisions

**Thread the per-connection identity into the per-request pipeline via the existing
seam.** `gateway.Request` carries an optional resolved `Identity *core.Context`; when
present, `Process` sets `disp.ResolveContext` to return it — the SAME D53 hook
peer-UEBA and the D85 fitness test use. No new pipeline mechanism: the identity is
enrichment the policy consults, exactly like risk. `toEvent` stamps the verified
pseudonym as the Event Subject, so the pipeline and telemetry finally carry a real
identity, not `sha256(src-IP)` (D84 closed at the data-plane).

**ACCESS fails CLOSED — the deliberate opposite of egress.** The egress forward proxy
fails OPEN on a pipeline error (D73/D17): a classifier failure must not deny all
egress, so the flow is forwarded and audited. The ACCESS proxy is the mirror image: a
pipeline error DENIES (403). Granting entry to an internal service on an error is the
one thing a Zero-Trust gate must never do — "never trust, verify", and an unverified
request is denied, not admitted. The two directions have opposite safe-failure
directions because they protect opposite things (availability of monitored egress vs
integrity of guarded access). This is stated, not incidental.

**Authentication, authorization, and device trust are separate gates.** The client
cert AUTHENTICATES (D86); the policy AUTHORIZES on role (D85); device posture is a
THIRD input, absent here (its producer is later) so a ZT policy that requires posture
still denies. This increment proves auth + role-authz; a policy that also required
`device_posture.has_posture` would deny every request until the posture producer runs
— the correct fail-closed default (D85).

## Risks / Trade-offs

- **Single fixed upstream.** A real access gateway fronts MANY internal services with
  per-service policy (microsegmentation) — that is the catalog (A.4). This increment
  proves the access MECHANISM against one upstream; the catalog is a routing + policy
  layer on top, not a change to this handler's core.
- **Body is buffered to classify AND forward.** Same bounded-buffer trade-off as the
  egress proxy (D73); DLP-on-access (scanning uploads to internal services) is a real
  bonus of running the body through the pipeline here.
