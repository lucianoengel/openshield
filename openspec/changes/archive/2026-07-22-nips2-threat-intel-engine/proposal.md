## Why

The gateway inspects flows for DLP content, but it has no notion of a *known-bad destination*: a flow
to a command-and-control domain or a flagged IP passes as long as it carries no sensitive content. That
is what makes the network plane "NIDS + inline HTTP DLP" rather than an IPS. ADR-8 is explicit — "without
signatures it is not an IPS," and NIPS-2 is to be sequenced with NIPS-1. This adds the signature /
threat-intelligence engine: match a flow's destination and request metadata against an operator-loaded
IOC feed, so the policy can block a flow to a known-bad indicator.

## What Changes

- A `ThreatClassification` on the pipeline `State` — a new detection dimension distinct from the DLP
  content classification (network threat is not content PII; conflating them would misuse the closed
  DLP detector enum, which exists precisely to avoid leaking *what* was detected).
- A closed `ThreatCategory` enum (IOC domain, IOC IP, URI signature) and a `ThreatMatch` carrying
  category + confidence + an opaque indicator id (never the matched content).
- An `internal/nips` threat-intel engine: an IOC feed (bad domains, IPs/CIDRs, URI substrings) loaded
  from an operator file, and a matcher over a flow's SNI/host, destination IP, and request path.
- A gateway threat-classify stage that runs the matcher on the network Event's metadata and records the
  threat matches, and a policy input (`input.threat`) so a rule can block a flow to a known-bad
  indicator. IOC matches are definitive (confidence 1.0), not probabilistic.

## Capabilities

### New Capabilities
- `network-threat-intel`: a signature/IOC engine that flags a flow to a known-bad destination or a
  request matching a network signature, so the policy can prevent it — what makes the gateway an IPS,
  not only a DLP inspector.

### Modified Capabilities
<!-- none -->

## Impact

- **Code:** a `threat.proto` (regenerated); `core.State.Threats` + `input.threat` in policy; a new
  `internal/nips` package (feed + matcher); a gateway threat-classify stage; IOC-feed loading wired into
  the gateway binary. Proven: a flow to a feed-listed domain/IP/URI is flagged and a policy blocks it; a
  clean flow is untouched; an absent feed produces no threats and no error (fail open, D73/D17).
- **Scope note (honest):** this increment matches on flow **metadata** — domain, IP, URI. **YARA-style
  body-content signatures** (matching the request/response payload) are a larger follow-up (they run in
  the sandboxed worker, like the DLP parser). Live **IOC feed refresh** (this loads a file at startup;
  auto-updating from a threat-intel source) is a noted follow-up. **NIPS-1 (the TPROXY inline data
  plane)** is the paired connector; its transparent-redirect setup is root/`CAP_NET_ADMIN`-gated
  (ADR-8) and validated out of this sandbox — this increment is the signature engine that runs behind
  whichever connector delivers the flow (the existing HTTP proxy today).
