## Why

Risk is single-domain. `PublishRisk` is called from exactly one place — the server-side peer-UEBA detector —
so the risk a Zero-Trust proxy applies to a request reflects behavioral analytics and **nothing else**. A
device with a killed process, a ransomware canary trip and a blocked C2 lookup carries the same risk as a
quiet one, because none of those domains feed the number the access decision reads.

That is the T2 continuous-verification loop (D89/D91) working within one domain and not across them — which
is the whole point of having an entity graph and a unified alert stream.

## What Changes

- **Risk is aggregated per ENTITY, across domains**, from the alerts every domain now writes (D241): a HIPS
  detection, a NIPS block and a UEBA anomaly on one asset compose into one number.
- **It is published for every alias of that entity**, so a consumer that knows the device pseudonym and one
  that knows the user identity both see it — the device⋈user link doing real work rather than only grouping
  incidents.
- **Severity buckets map to a risk floor**, reusing the existing four-bucket vocabulary rather than
  inventing a second scale, with recency weighting so a week-old critical does not pin an asset forever.
- **Peer-UEBA risk still publishes as it does today.** Entity risk is additive: the highest of the two wins,
  so turning this on cannot LOWER the risk a policy already sees.

## Capabilities

### Modified Capabilities

- `peer-ueba`: risk publication becomes cross-domain and entity-keyed rather than UEBA-only and
  subject-keyed.

## Impact

- **Code:** `internal/controlplane` (the aggregation + publication), driven from the same scheduled loop
  SOAR-2 added.
- **Decisions:** completes the **D89/D91** T2 loop across domains; builds on **D241** (every domain writes
  the unified stream), **D203** (the entity graph), and **ADR-10** (one severity vocabulary).

### What this change does NOT claim or cover

- **It is a heuristic, not a measurement.** Severity buckets and a recency weight are a defensible ordering,
  not a calibrated probability of compromise. Nothing downstream may treat the number as evidence, and the
  policy still decides what a given risk means.
- **It inherits the domain labels' coarseness** (D241): three "domains" means three of OpenShield's labels,
  not three independent attacker behaviors.
- It does **not** decay continuously — risk is recomputed on the correlation interval, so it moves in steps.
- It does **not** feed risk back into the endpoint's own decisions; the consumer today is the access proxy.
  An endpoint reading fleet risk is a separate design question (the server informs, the endpoint decides).
- It does **not** replace peer-UEBA risk; a deployment with analytics off gets alert-derived risk only.
