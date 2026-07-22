## Context

The gateway builds a `NetworkSubject` Event (SNI/host, dst IP, path, ...) and classifies the body via
the worker into `State.Classification`. The policy reads the classification. A threat-intel match is a
*different kind* of detection — a known-bad destination, not sensitive content — so it gets its own
State field and policy input rather than being forced into the DLP detector enum.

## Goals / Non-Goals

**Goals**
- A `ThreatClassification` (category + confidence + opaque indicator id) on `State`, exposed to policy.
- `internal/nips`: an IOC feed (domains, IPs/CIDRs, URI substrings) + a matcher over flow metadata.
- A gateway threat-classify stage; IOC-feed loading in the binary.
- Prove: a known-bad flow is flagged and blockable; a clean flow is untouched; no feed = no threats.

**Non-Goals**
- YARA-style body-content signatures (a worker-side follow-up).
- Live feed refresh (loads a file at startup; auto-update is a follow-up).
- The NIPS-1 TPROXY inline connector (root-gated, paired but separate; the engine runs behind any
  connector that delivers a flow).

## Decisions

### D1 — Threat classification is a distinct dimension, not a DLP detector
The DLP `DetectorType` is a closed enum specifically so a detector name cannot leak *what* it detected.
A network IOC is the opposite kind of signal — the indicator (a bad domain) is public threat-intel, and
the flow's destination is already in the Event metadata. Forcing IOCs into the DLP enum would be a
category error and would muddy both. So `ThreatClassification` is its own message on `State.Threats`,
with its own closed `ThreatCategory` enum. The matched indicator is carried as an opaque `indicator_id`
(a feed/rule id an analyst can trace), never the matched string, keeping the classification-crossing
free of raw matched content — the same discipline as the empty `matched_text`.

### D2 — IOC matches are definitive, not probabilistic
A DLP detector is probabilistic (a regex + checksum yields a confidence). A known-bad indicator match is
definitive: the destination *is* on the feed. So threat matches carry confidence 1.0, and the policy can
treat a threat match as a hard signal (unlike a DLP hit, which D4 forbids treating as certainty). The
confidence field is kept for uniformity and for future weaker signatures (e.g. a heuristic URI rule).

### D3 — Matcher is metadata-only and worker-free
Domain/IP/URI matching needs only the Event's network metadata, not the body, so the threat-classify
stage does not call the worker — it is cheap and cannot fail on a parse. Domain matching is exact plus
parent-suffix (a hit on `evil.com` also matches `c2.evil.com`); IP matching is exact plus CIDR
membership; URI matching is a case-sensitive substring on the path. The feed is an operator-loaded file
(the roster model), one indicator per line with a category prefix.

### D4 — Fail open: no feed, no threats, never an error
Consistent with the egress fail-open (D73/D17): if no feed is configured the engine is inert (no threat
matches, the stage is not registered), and a malformed feed line is a load-time error (surfaced, like
the enrollment loader) — but at request time the engine never errors the pipeline. A threat match adds a
signal for the policy; it never itself blocks (the policy decides), and its absence never denies.

## Risks / Trade-offs

- **Metadata-only** — cannot catch a bad payload to a benign-looking host; that is the YARA-body
  follow-up, stated. Still, destination-based IOC blocking is the highest-value, lowest-FP network
  prevention.
- **Static feed** — stale until reload; the file model matches the posture roster / enrollment file, and
  live refresh is a noted follow-up.

## Migration Plan

Additive: one proto message + enum (regenerated), one `State` field (nil when no engine runs — existing
pipelines unaffected), one policy input (absent when no threats), a new package, a gateway stage, binary
wiring. No change to existing behavior unless a feed is configured and a policy consults `input.threat`.

## Open Questions

- Whether threat matches should also feed the audit ledger as their own record (vs only the Decision).
  Deferred; the Decision already records the blocked flow.
