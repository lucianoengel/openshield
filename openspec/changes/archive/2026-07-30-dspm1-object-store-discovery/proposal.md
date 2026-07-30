# OpenShield cannot answer "where is my sensitive data"

## Why

The enterprise gap assessment named this the largest **name-versus-capability** gap in the product, and it
is the first question asked of anything called a Data Security Platform.

OpenShield classifies data **in motion past an interposition point** — a file being written, a paste, a
print job, an HTTP upload, an SMTP message, a DNS query. Data at rest is invisible to it. The only cloud
surface that exists is *log ingest* (`internal/connectors/cloudtrail`) plus AWS-key secret detection in
`internal/classify/secrets.go`; there is no S3, Azure Blob, GCS, M365 or Google Workspace enumeration
anywhere. A bucket full of customer PII is invisible until somebody touches it on an instrumented host.

**And it is the strongest available test of the D26/D69 fitness claim** — better than the S3 connector T-014
dismissed as isomorphic. Every producer in the tree today is **pushed**: the kernel, a socket or a listener
hands it an event and it reacts. A discovery connector **pulls and enumerates on a schedule**, which is a
genuinely different shape. T-004 tested the claim on paper against peer-UEBA; nothing has tested it against
a new producer shape in code. If this forces a core change, the ten-year claim needs revisiting — and
finding that out is a result, not a setback.

## What changes

`internal/connectors/objectstore` — an S3-compatible discovery connector:

- **Enumerate** objects (ListObjectsV2), bounded per sweep.
- **Fetch a bounded prefix** of each object (ranged GET).
- **Emit an Event per object**, with the bytes going to the engine's content store so the SANDBOXED WORKER
  classifies them and nothing else does (D72) — the same seam `smtpsource.go` uses.
- **Sweep on an interval**, wired into `cmd/openshield-engine` behind configuration, off by default.

The connector itself never classifies, never logs object content, and never puts content on the Event
(D10/D29).

## Impact

- New capability: **object-discovery**. Affects **event-contract** if the fitness question below goes that
  way.
- Wired into `openshield-engine`, off unless configured.
- **No new dependency** — see the design. Migration: none.

## The open design question, deliberately not pre-decided

A discovered object is `store + bucket + key`. The existing `FilesystemSubject` is a oneof whose usable arm
here is `resolved_path string`.

- **Reuse it** (`s3://bucket/key` as the path): no contract change, and structure is lost — a policy that
  wants "bucket = finance-exports" has to parse a string.
- **Add an `ObjectSubject`**: structured, and a change to the core Event contract.

**The plan is to try the reuse first and record the verdict**, because pre-deciding to add a message is
assuming the answer to the question this ticket exists to ask. Whichever way it lands gets written down
next to the T-004 verdict.

Separately, a new `EventKind` **is** intended: `EVENT_KIND_OBJECT_DISCOVERED`. Reusing `FILE_OPENED` would
be a lie — nobody opened it, a scanner read it — and the distinction matters downstream, because "this data
exists here" and "someone touched this" deserve different policy. Adding a kind is additive and is precisely
how kinds 7, 8, 9, 13 and 14 arrived; it is a producer declaring itself, not a core change.

## Honest limits, stated up front

- **Discovery without ACCESS CONTEXT is half of what DSPM buyers mean.** "Where is the sensitive data" and
  "who can reach it" are two features. This is the first; bucket policy/ACL analysis is not in scope and
  should not be implied.
- **One store.** S3-compatible only. Azure Blob, GCS, M365 and Google Workspace are each their own
  connector, and claiming "cloud discovery" off the back of this would be the overclaiming the doc guard
  exists to prevent.
- **A prefix, not the whole object.** Sensitive content past the ceiling is invisible, exactly as it is for
  the inline file gate (D16: friction, not a guarantee). The ceiling is configurable and the limit is real.
- **Sampling is bounded, so coverage is partial by construction.** A sweep with a max-objects ceiling has
  NOT scanned the bucket, and the connector must report what it skipped rather than let a partial sweep read
  as a clean one (D31).
- **No incremental state in this increment.** Every sweep re-enumerates from the start; there is no
  "only what changed since last time". That is a real cost on a large bucket and is the obvious follow-up.
- **Read-only.** No remediation, no quarantine, no bucket mutation of any kind.
