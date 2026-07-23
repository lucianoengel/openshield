## Context

`dns.ParseQuery(msg)` safely decodes a query's first question (bounded name, no compression-pointer
chasing) into `{Name, QType}`. `nips.Feed.Match(host, "", "")` matches a domain (exact + parent-suffix)
against the operator IOC feed. A DNS response reuses the query's transaction ID and question section.
NIPS-8 combines these into a forwarding resolver that sinkholes a blocked name.

## Goals / Non-Goals

**Goals:** a UDP resolver that forwards normal queries upstream and sinkholes a blocked domain (NXDOMAIN),
fail-open (never blackhole on a parse/classify problem), IOC-feed-backed.

**Non-Goals (later increments):** cache + upstream failover; the transparent `:53` redirect; a
sinkhole-IP walled garden; TCP/DoT/DoH; a bypass watchdog.

## Decisions

1. **NXDOMAIN sinkhole, built from the query.** A blocked domain gets a response cloned from the query's
   header (same transaction ID and question) with `QR=1`, `RCODE=3` (NXDOMAIN), and zero answers. The
   client sees a well-formed "this name does not exist" and does not connect — the standard RPZ sinkhole.
   Returning a sinkhole IP (walled garden) is a deferred option; NXDOMAIN is the simplest preventive
   answer and needs no owned sinkhole host.

2. **Fail-open is the safety invariant.** The resolver forwards a query to the upstream UNLESS it is
   certain the domain is blocked: a message it cannot parse, a non-query, or a domain the block set does
   not match is forwarded. A resolver that dropped or NXDOMAIN'd on any uncertainty would break name
   resolution for the whole fleet — far worse than missing one sinkhole. This is the D73/D17 discipline
   the roadmap makes a precondition for DNS prevention. (If the UPSTREAM itself is down, the query fails
   as it would with any resolver — that is an upstream outage, not a sinkhole.)

3. **Injectable block function, IOC-feed-backed in production.** `Resolver` holds `blocked func(name
   string) bool` — production wires it to `feed.Match(name, "", "") != nil` (hot-reloadable via the
   existing feed reloader), tests inject a set. This keeps the resolver decoupled from the feed and
   unit-testable without one.

4. **Per-query goroutine, bounded.** Each datagram is handled in its own goroutine (a forward is a
   blocking round-trip to the upstream); a per-forward timeout bounds a slow upstream so a stuck forward
   never wedges the reader. The read buffer is bounded (a UDP DNS message is <= 512 classically, 4096 with
   EDNS0 — a 4 KiB buffer covers it; a larger message is truncated, which the client retries over TCP,
   deferred).

## Risks / Trade-offs

- **UDP only (increment 1).** A client that falls back to TCP (large response, truncation) is not served;
  TCP DNS is a deferred increment. Most lookups are UDP.
- **No cache.** Every query is forwarded upstream (except sinkholed ones), adding the upstream's latency.
  A cache is a deferred increment; correctness (forward or sinkhole) does not depend on it.
- **NXDOMAIN vs sinkhole-IP.** NXDOMAIN prevents the connection but gives the client no walled-garden
  landing page; a sinkhole-IP option is deferred.
- **Binding `:53` needs privilege** (or `CAP_NET_BIND_SERVICE`); the resolver logic is port-agnostic and
  tested on a high port, with a privileged bind proven on the VM. The transparent redirect that steers
  clients to this resolver (DEPLOY-1) is explicitly NOT shipped until this resolver exists (it now does).
