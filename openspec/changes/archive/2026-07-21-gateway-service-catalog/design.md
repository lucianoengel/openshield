## Context

D87's `AccessProxy` fronts one fixed upstream and authorizes on identity/role. Real
microsegmentation is per-SERVICE: the same identity may reach one internal service and
not another. That needs (a) a catalog routing a request to the right service, and (b)
the policy seeing WHICH service is targeted so it can authorize per-service.

## Goals / Non-Goals

**Goals:** route to many internal services; authorize per-service on identity; an
unknown service is refused, not forwarded.

**Non-Goals:** binary access-mode wiring (A.4b); OIDC; posture; risk loop; path/wildcard
routing.

## Decisions

**The catalog routes by exact host; an unknown service is 404, not forwarded.** A
client requests a service by its host (`payroll`, `wiki`); `Catalog.Resolve` maps it to
the internal upstream. A host NOT in the catalog is refused with 404 — the access
gateway fronts an explicit allow-list of services, never an open relay to arbitrary
internal hosts (that would be an SSRF/pivot surface). Exact-match host routing here;
path-prefix and wildcards are a later refinement.

**The policy authorizes per-service because it SEES the service.** `Request.Host` is set
to the resolved service, so `toEvent` stamps it on the NetworkSubject and `buildInput`
exposes `input.event.{host, method, path}`. The policy then expresses microsegmentation
directly: `allow if role == "finance" and event.host == "payroll"`. Same identity,
different service, different verdict — the core Zero-Trust property, identity-based not
IP-based (D84's requirement).

**Exposing the URL path to the LOCAL policy is not a boundary crossing.** D77 redacts
the URL path from TELEMETRY because a path+query is content-like and telemetry leaves
the host. The POLICY runs in-process and produces a boundary-safe Decision (no content
in it, D14); giving it the path enables per-endpoint authz (`/admin` vs `/`) without any
content leaving the host. Telemetry redaction (D77) is unchanged — the two are different
surfaces.

## Risks / Trade-offs

- **The catalog is an allow-list the operator must maintain.** A service not in the
  catalog is unreachable through the gateway — which is the point (default-deny topology),
  but it means onboarding a service is a catalog edit. Acceptable and correct for ZT.
- **Host-based routing trusts the request Host header.** The gateway resolves the service
  from Host; a client could send an arbitrary Host, but it can only reach services IN the
  catalog, and the per-service policy still authorizes — so a spoofed Host reaches at most
  a catalogued service the identity is authorized for. Stated.
