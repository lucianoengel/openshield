# Enterprise gap assessment

> **What this is.** A comparison of OpenShield at `HEAD` against what a large enterprise actually
> buys when it buys a Data Security Platform + XDR + SOAR. It is deliberately written from the
> BUYER's side, not the builder's: the question is not "is this well engineered" (the roadmap's
> maturity table answers that) but "would this survive an enterprise evaluation, and if not, what
> exactly disqualifies it".
>
> **Companion to** [`architecture-roadmap.md`](architecture-roadmap.md) (the forward plan and the
> self-assessed per-domain maturity) and [`unwired-audit.md`](unwired-audit.md) (code that exists
> but nothing runs). This file adds the axis neither of those has: **what a competitor ships that
> we do not have at all.**

## Method, and its limits

Every OpenShield-side claim below was checked against the tree at `HEAD` — grep/read of the actual
package, not inference from a spec or a commit message. Where a claim is about the *incumbent*
baseline it comes from general product knowledge of the category, not from a lab evaluation; those
are the softer claims and are marked where the distinction matters.

**Two limits worth stating plainly.** First, nobody ran a paid competitor next to this. A feature
matrix assembled from product knowledge systematically *overstates* incumbents (marketing pages
describe intent) and *understates* them (nobody documents the hundred operational affordances that
make a product usable at 50,000 endpoints). Second, "enterprise grade" is not one bar. An MSSP, a
regulated bank, and a 200-seat startup fail on different items in the list below. Where an item is
a hard gate for a specific buyer, it says so.

## The baseline

There is no single product to compare against, because no single product covers OpenShield's stated
scope. The realistic enterprise stack it is positioned against is a composite:

| Slot | Typical incumbents |
|---|---|
| Endpoint EDR/XDR | CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne |
| Endpoint + network DLP | Symantec DLP, Forcepoint ONE, Microsoft Purview DLP, Falcon Data Protection |
| DSPM (data at rest) | Varonis, Cyera, BigID, Purview Data Map |
| SSE (SWG/CASB/ZTNA) | Netskope One, Zscaler, Cloudflare One |
| SIEM + SOAR | Sentinel, Splunk ES, Cortex XSIAM, Falcon Next-Gen SIEM + Fusion |

OpenShield's actual thesis — *one pipeline, one auditable decision record, across endpoint + network
+ identity* — is a real architectural differentiator, and the composite above is precisely what it
argues against. That thesis is not evaluated here; the gaps are.

---

## Gate items — the gaps that end an evaluation regardless of detection depth

These are not feature deltas. Each one, on its own, removes OpenShield from consideration for a
class of buyer before any detection quality question is asked.

### 1. Linux only. There is no Windows or macOS endpoint agent.

**Verified.** Every non-Linux file in the tree is a small refusal stub — the largest,
`internal/agent/execmon/execmon_other.go`, is 46 lines. `make cross-compile` proves the tree
*compiles* for `windows/amd64` and `darwin/amd64`; it does not produce an agent that observes
anything. `fanotify`, `openmon`, `execmon`, the clipboard reader, the USB enforcer, TPM attestation,
the process killer and the sandbox all have `!linux` stubs that return "unsupported".

This is the single largest gap in the document. Enterprise endpoint estates are Windows-majority;
an endpoint DLP or EDR product that cannot see a Windows laptop is not an endpoint product to a
buyer, whatever it does on servers. It is also the most expensive gap to close — ETW + minifilter
on Windows, EndpointSecurity framework on macOS — and closing it means the *second* and *third*
implementations of every observation surface, which is the work the current architecture has not
yet been tested against.

**And the one non-Linux observation surface that does exist is never executed on the platform it
exists for.** `internal/connectors/filewatch` is a portable stdlib-polling file connector, wired
into the engine by the `!linux`-tagged `cmd/openshield-engine/watcher_other.go` — so on Windows and
macOS the engine observes files through it rather than exiting. But the CI matrix runs
`go build` + `go vet` on `windows-latest` and **no tests at all** (the step is guarded
`if: runner.os != 'Windows'`, with a recorded and reasonable rationale — the suite is POSIX by
nature). macOS does run the unit suite, so `filewatch`'s own tests execute there; nothing runs the
*engine* on either platform. The net position: the only code path a Windows deployment would
depend on has its behaviour proven exclusively on Linux.

That is defensible while Windows is explicitly out of scope, and it is exactly the thing that stops
being defensible the moment Windows enters scope — worth knowing before, not after.

Honest counter-position: OpenShield today is a strong **Linux server/workload** data-security
product, and that is a real, under-served market (the incumbents' Linux agents are mostly ports).
Positioning it that way is truthful and defensible. Positioning it as an endpoint DSP is not.

### 2. Operator authentication is mTLS client certificates only. No SSO, no SCIM.

**Verified.** `internal/transport/tlsconf` sets `ClientAuth: tls.RequireAndVerifyClientCert`, and
the operator's *role* is carried in the issued certificate — `internal/provision/provision.go`
defines `RoleAnalyst` / `RoleResponder` / `RoleAdmin` (with a legacy `operator` ranking below), and
`internal/controlplane/views.go` enforces the ordering. There is **no SAML anywhere in the tree**
(zero matches), and the only OIDC is in `internal/gateway/identity` — that authenticates ZTNA
*subjects* passing through the access proxy, not operators logging in to the platform.

Two distinct problems, and the second is worse than the checkbox:

- **The checkbox.** Enterprise IAM teams gate on SSO (OIDC or SAML) and SCIM deprovisioning. "We
  issue you a client certificate" fails procurement at most large organizations regardless of
  whether it is cryptographically better, because the control they are buying is *centralized
  joiner/mover/leaver*, not transport security.
- **The operational defect.** Because the role lives *in the certificate*, a role change requires
  re-issuing a certificate, and a demotion is not effective until the old certificate expires or is
  revoked. There is no "revoke this analyst's responder rights now" primitive. For a product whose
  pitch is an auditable decision record, an authorization change that takes effect on a
  certificate-lifetime delay is a real hole, not a missing integration.

### 3. No multi-tenancy. Zero tenant or organization scoping in the data model.

**Verified.** `tenant_id`, `TenantID`, `org_id`, `OrgID` — **zero matches** across `internal/`,
`cmd/`, and the migrations. Every table is single-tenant by construction.

This is a **deliberate open-core reservation** — `internal/enterprise/README.md` reserves
multi-tenancy per D21 — and recording it as such is correct. But the reservation has a consequence
worth stating in the buyer's language rather than the licensor's: an MSSP cannot deploy the open
core at all, and a large enterprise that needs subsidiary or regional segregation (common, and
sometimes legally required) cannot either. The deliberate choice is a business decision about where
revenue lives; it is still a gap in what the open product can do.

The retrofit cost is also worth naming now rather than discovering later: adding a tenant dimension
to a schema after ~76 capabilities have written against it is the kind of migration that touches
every query and every index, and the hash-chained ledger makes it harder still (a chain per tenant,
or a chain with tenant-scoped reads).

### 4. No data-at-rest discovery. OpenShield cannot answer "where is my sensitive data".

**Verified.** The only AWS surface is **log ingest** — `internal/connectors/cloudtrail` and
`internal/controlplane/cloudtrail_ingest.go` — plus AWS-key *secret detection* in
`internal/classify/secrets.go`. There is **no** S3, Azure Blob, GCS, M365/SharePoint/OneDrive, or
Google Workspace object enumeration (zero matches for `azure`, `gcs`, `graph.microsoft`,
`workspace`). Nothing walks a data store and reports what is in it.

Every product in the DSPM slot leads with exactly this, and it is the first question a CISO asks a
"Data Security Platform". OpenShield classifies data **in motion past an interposition point** — a
file being written, a paste, a print job, an HTTP upload, an SMTP message, a DNS query. Data sitting
in a bucket, a share, or a SaaS tenant is invisible to it until someone touches it on an
instrumented host.

This is the gap where the product's *name* and its *capability* diverge most, and unlike the
platform gap it is not architecturally hard — a discovery connector that enumerates an object store
and feeds the existing classifier is isomorphic to what exists (which is exactly what the D26/D69
fitness argument predicts). The reason it is absent is that it was never queued, not that the
pipeline resists it.

---

## Feature deltas — real gaps that shape a scorecard but do not gate

### Classification

- **No trained/ML classification and no semantic matching.** Verified: no ONNX, no embeddings, no
  model inference anywhere. Detection is regex + checksum validators + EDM/IDM exact and document
  fingerprinting + keyword proximity. This is a deliberate D5 call (endpoint viability) and the
  precision of checksum-validated national IDs is genuinely better than a naive classifier — but
  "trainable classifier" and, increasingly, "LLM-assisted classification" are RFP lines, and
  unstructured-document sensitivity (a contract, a board deck) is not reachable by pattern matching.
- **No OCR, no image classification.** Verified absent. A screenshot, a photographed screen, and a
  scanned-PDF passport are all invisible. Screenshot exfiltration is one of the most common real
  insider paths and it is untouched.
- **No detection-content portability.** `internal/signature` is YARA-*style*, not YARA; there is no
  Sigma import (zero matches). An enterprise with an existing detection library would have to
  rewrite it, which is a migration cost most SOCs will not pay.

### Response and operations

- **No agent self-protection.** D16 states the position honestly — detection, not prevention, and
  ineffective against root. Every enterprise EDR ships driver-backed process protection and an
  uninstall password. The honesty is a genuine differentiator in the trust conversation and a
  genuine loss on the scorecard; both are true.
- **No compliance reporting packs.** Retention and reporting exist as capabilities; PCI/HIPAA/
  GDPR/SOX report templates and auditor-facing evidence export do not. Reserved for enterprise per
  D21, same caveat as multi-tenancy.
- **No UI.** Known, deliberate, and last in the plan — but worth stating in this document's terms:
  every finding OpenShield produces is currently consumed through a CLI and SQL. Until the UI
  lands, the product is evaluable by engineers and not by the analysts who would operate it.

### Coverage

- **Email is a capture listener, not an MTA integration.** `cmd/openshield-engine/smtpsource.go`
  wires `internal/connectors/smtp` to a real capture listener with session ceilings and a
  concurrency cap — this is genuinely wired, not shelf-ware. What is absent is the *enterprise
  deployment shape*: a milter or MTA hook that can quarantine, redirect, or encrypt a message, and
  journaling/API integration with M365 or Gmail, which is how outbound email DLP is actually
  deployed.
- **CASB is inline-only.** Content-aware upload blocking to unsanctioned clouds exists at the
  gateway. API-mode CASB — out-of-band scanning of a SaaS tenant plus retroactive remediation of
  what is already there — does not, and is the half most SaaS DLP buyers mean.
- **No browser visibility.** `BrowserUploadStarted` was explicitly cut in Phase 1 and recorded as a
  cut. Without a browser extension or a TLS-terminating proxy in the path, in-browser actions
  (paste into a web form, upload from a web app, a generative-AI prompt) are visible only as much
  as the network gateway can see, which for a modern SaaS app is very little.
- **NIPS grammar and modern protocols.** Already named as enrichment in the roadmap: no full
  Suricata grammar, no HTTP/2 or QUIC, no JA3.

---

## What is NOT a gap, and should stop being counted as one

- **Single-instance control plane.** It is not single-instance. `internal/controlplane/leader.go`
  implements leader election over a Postgres advisory lock with standby polling and lease-loss
  detection (PLAT-2b), so a warm standby exists. The scale ceiling is unmeasured — that is a
  different and real question — but the availability story is not absent.
- **Multi-tenancy, managed Hub, compliance packs.** Deliberate open-core reservations under D21,
  documented in `internal/enterprise/README.md`. They are gaps in the open product's reach, not
  oversights, and this document counts them once (above) rather than as evidence of immaturity.
- **Observe-only defaults / fail-open.** D1, D17, D18. Incumbents ship blocking defaults and the
  contrast reads as weakness on a matrix. It is a deliberate safety posture with a recorded
  rationale, and the inline prevention plane exists for when a deployment wants it.

---

## Where the fleet-simulation claim overstates what is tested

Recorded here because it is the kind of drift this document exists to catch. The
`fleet-simulation` capability describes "N agent **containers** enrolling with their own
identities". The reality is N agent **processes** on one host; podman is used for Postgres and NATS
only, and the largest fleet exercised anywhere in the suite is **six** (five quiet peers plus one,
`test/integration/analytics_test.go`).

The fleet *properties* that the suite asserts — per-agent identity, enrollment, heartbeat,
divergence from a peer baseline — are genuinely tested, and testing them with processes rather than
containers is a reasonable engineering choice. What cannot be tested in that shape, and is
therefore unproven, is the set of failures that only exist between machines: **network partition
and rejoin, clock skew between agents and the control plane, per-node resource limits under real
contention, and offline-queue drain after a real disconnection.** Those are exactly the failures an
enterprise pilot finds first.

The recommendation is not "N=20 for its own sake". It is that the four properties above each need a
test whose failure mode is a partition or a skew, and a container topology is the cheapest way to
get one.

---

## Prioritized recommendation

Ordered by *evaluation outcome changed per unit of work*, which is not the same as by size.

1. **Data-at-rest discovery (one object store).** Closes the largest name-versus-capability gap,
   is architecturally cheap because the classifier already exists, and doubles as the strongest
   available test of the D26/D69 fitness claim — a discovery connector is a genuinely new *shape*
   of producer (it pulls and enumerates rather than being pushed events).
2. **SSO for operators, and move the role out of the certificate.** The role-in-certificate
   revocation hole is a real defect independent of the SSO checkbox, and fixing it is the
   prerequisite for SSO anyway.
3. **The four unproven distributed properties** (partition, clock skew, node limits, offline
   drain), via a container topology. This is the item most likely to prevent a bad surprise rather
   than win a comparison.
4. **Pick and state the positioning.** "Linux workload data security" is true today and
   defensible; "endpoint DSP" is not true until a Windows agent exists. This is an owner decision
   and an owner-voice task, not a builder ticket — but every item above is prioritized differently
   depending on the answer, so it is the highest-leverage decision in the list.
5. **A Windows agent** is the largest gap and deliberately last here: it is worth starting only
   after (4) says the endpoint market is the target, because it is a multi-quarter commitment that
   re-tests every observation abstraction in the tree.
