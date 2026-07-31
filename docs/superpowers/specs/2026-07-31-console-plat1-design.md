# PLAT-1 · The OpenShield Console — design

**Date:** 2026-07-31 · **Status:** draft for review · **Verified against:** `15884d8` (D426)
**Supersedes:** the one-paragraph PLAT-1 entry in `docs/architecture-roadmap.md` (🔒 Parked)

Reviewed adversarially by an architecture critic and a security auditor against the tree at HEAD. Their
findings are folded in; §11 records what was retracted and what was disputed.

---

## 1. What is actually true today

PLAT-1 reads as a UI ticket. It is not. Roughly 40% of the work is backend, and one part of it is a
**shipped defect that already breaks ZT-7 SSO operators**.

### 1.1 The blocker: an authenticated operator identity does not reach the handlers

`requireTier` (`internal/controlplane/views.go:131-158`) authenticates by client certificate **or** OIDC
bearer token, resolves the role, and then calls `h.ServeHTTP(w, r)` — **discarding `auth.identity`**. It is
never placed on the request context.

Eight handlers then derive identity independently, from TLS only:

```
internal/controlplane/alert_ack.go:55      internal/controlplane/incidents.go:175
internal/controlplane/cases_http.go:66     internal/controlplane/savedsearch.go:233
internal/controlplane/dsar.go:115          internal/controlplane/soar2.go:147
internal/controlplane/timeline.go:186      internal/controlplane/views.go:186
```

`operatorIdentity(state *tls.ConnectionState)` (`views.go:166-172`) returns `""` when there is no peer
certificate, and every caller turns that into `401 client certificate required`.

**Consequence, today, with no console involved:** an operator authenticated by ZT-7 SSO (D373) passes the
tier gate and is then refused by `/alerts/ack`, `/incidents/ack`, `/incidents/transition`,
`/incidents/timeline`, `/cases/*`, `/searches/save`, `/subject` and `/view`. SSO operators can read the
queue and do almost nothing else. This is unnamed in the roadmap, the register and the specs — the same
shape as D415/D417/D418.

### 1.2 The trap: fixing 1.1 naively breaks four-eyes

The two credential paths mint **different identity strings for the same human**:

- certificate → `"operator:" + CommonName` (`views.go:171`)
- OIDC → the raw `sub` (`operator_roles.go:307-314`)

Four-eyes is a string comparison inside the SQL predicate — `approvals.go:119`:

```sql
UPDATE approvals SET state=$1, approver=$2, resolved_at=now()
 WHERE id=$3 AND state='pending' AND expires_at > now() AND requester <> $2
```

Thread the bearer identity through unchanged and one human requests a case closure, a `CONTAIN` intent, or
a fleet `ENFORCEMENT_DISABLE` from the CLI as `operator:alice`, then approves it from the console as
`alice`. Two rows, two strings, predicate satisfied. **Two-person control collapses on the three most
consequential acts in the product.** `docs/threat-model.md:143` grounds this control in *"the requester and
the approver are taken from client CERTIFICATES, never from a request field."*

It is latent only because bearer operators cannot currently reach `actor()` at all. §1.1 and §1.2 must
therefore be fixed as **one change**, never sequentially.

### 1.3 Supporting gaps

| Needed by any console | State at D426 |
|---|---|
| Entity / XDR graph over HTTP | **Absent.** `internal/xdr` has no HTTP surface; entity graph (D203) and per-entity risk (D255) are DB-only. |
| Fleet / agent inventory | **Absent.** Only `GET /overdue?threshold=`. |
| Platform health (leader / broker / ingest) | **Absent at operator tier.** `/metrics` is behind a *separate* constant-time bearer token (PLAT-4b, `metrics_auth.go`), not the operator session. The Overview's first tile has no data source. |
| Keyset pagination | **Absent.** `maxSearchLimit = 1000` (`operator_read.go:281`), `ORDER BY received_at DESC, id DESC LIMIT $n`, no cursor, no `has_more`. |
| Break-glass / kill-switch surface | **Absent.** `agent_enforcement` is persisted (`heartbeat.go:72`) and `enforcement_suppressed` counters exist, with no read surface. |
| Operator role management | CLI-only (`openshield-server operator-role`). |
| Enroll token issue/revoke, feed ingest, fleet-control | CLI-only. |
| Playbooks | A polled file (`OPENSHIELD_PLAYBOOKS`). No read/validate/dry-run API. |
| Decision replay | CLI-only (`openshieldctl replay`). |
| i18n | **Absent.** No catalog, no locale handling. |
| Topology / sites / zones | **Absent.** `grep -riE "topology\|site_?id\|zone_?id"` over `.go` returns nothing. |
| Streaming | Absent — and deliberately not added (§6). |

**One genuine unreachable route:** `/report/response` (SOAR-6 MTTA/MTTR) is registered on the inner mux
(`operator_read.go:231`) and absent from the outer tier-gated mount list in `enroll_http.go`. Confirmed by
grep at HEAD.

### 1.4 The guard that should have caught it is a hardcoded list

`internal/controlplane/operator_routes_test.go:15` iterates a literal six-item slice
(`/alerts`, `/search`, `/events`, `/incidents`, `/overdue`, `/subject`). Its own comment says it exists
because `/events` once shipped registered-but-not-mounted. It has never been extended, which is why
`/report/response` shipped unreachable.

`http.ServeMux` cannot be enumerated, so the fix must be structural: make the route set **data** — one
`var operatorRoutes = []route{{Pattern, MinTier, Handler}}` that both the inner handler and the outer TLS
mux iterate — so a missed mount becomes impossible by construction rather than by a test someone has to
remember to extend.

---

## 2. Architecture

```
apps/console/            React 19 + TypeScript + Vite + pnpm
  TanStack Query/Table   server state, keyset cursors, virtualized grids
  react-i18next + ICU    message catalog (English ships; packs added later)
        │  pnpm build → apps/console/dist/   (pinned, network-less, reproducible)
        ▼
internal/console/        embed.FS + strict-CSP static handler
        │
        ▼
openshield-server        same origin as the operator API — no CORS, no second listener
```

- **Same origin, same mux, same tier gate.** No CORS, and no credential reachable from JS.
- **Go must build without Node.** A build tag serves a stub when `dist/` is absent; `go build ./...` on a
  clean checkout never requires a JS toolchain.
- **No CDN.** Everything self-hosted, strict CSP. A security product whose console pulls a third-party
  script fails its own bar.
- `@xyflow/react` is **not** a console dependency — it arrives with the topology lane (§7), which is
  sequenced separately and gated on its own decision.

### 2.1 Authentication — one principal, two credentials

ZT-7 already shipped operator SSO (D373), authority-out-of-certificate (D372), token binding (D379) and
SCIM deprovisioning. Missing is only the **browser** flow: today's OIDC path verifies a bearer token the
caller already holds.

- **OIDC Authorization Code + PKCE**, with `state` bound to a pre-auth `__Host-` cookie, `nonce`, and the
  callback `iss` check (OAuth 2.1 mix-up defence).
- **Server-side session**: `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Strict`, idle + absolute
  timeout, server-side revocation on logout.
- **Authorization unchanged.** `resolveOperatorRole` against `operator_roles`, fresh per request, uncached,
  revocation-wins, `OPENSHIELD_OPERATOR_ROLES_STRICT` honoured.
- **No group claim, no `roles` claim, no default tier is ever read from a token.** ZT-7 spent three changes
  removing authorization from the credential path. A first SSO login with no `operator_roles` row gets
  "your identity is known, you have no authority; an administrator must grant it" — not a default role.
- **The console's OAuth client is a separate component from the bearer verifier.** The session is never
  derived by re-presenting the IdP token to `authenticateOperator`, and a token whose `aud` equals the
  console `client_id` is refused on the bearer path — otherwise setting
  `OPENSHIELD_OPERATOR_OIDC_AUDIENCE` to the console client id turns any ID token minted for that client,
  for any user, into an operator credential.
- **CSRF**: double-submit token in an `X-OpenShield-CSRF` **header** checked by middleware on every
  non-GET, plus an independent `Origin` check. A header keeps every existing route signature unchanged —
  today's write routes take parameters from the query string and have no body to carry a token in.
- **`SameSite=Strict` is kept**, and the "paste a link into a ticket" requirement is solved with a
  same-origin landing route rather than relaxing the cookie to `Lax`.

**Canonical principal.** One identity function serves `resolveOperatorRole`, `actor()` and the session
layer, emitting a **namespaced** principal (`cert:<CN>` / `oidc:<issuer>#<sub>`), with an
`operator_identities` table linking principals to one account. Four-eyes compares **account**, not
principal string. `operator_roles` gains an issuer/method discriminator so an IdP subject can never
collide with a certificate CN.

**Invariants, each with the mutation that proves it:**

| Invariant | Mutation that must make the test fail |
|---|---|
| The console can never grant an authority `operator-role set` did not grant | make the session mint carry a tier from the OIDC `groups` claim |
| The same human cannot satisfy four-eyes with two credentials | compare principal strings instead of account id |
| An unmounted operator route cannot ship | delete an entry from the outer mount loop |

The four-eyes test must first assert the request **reached the tier gate** — otherwise it passes
vacuously, the trap `INVARIANTS.md:114` describes for INV-4.

### 2.2 DPoP — fail closed, stated

`OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP` (`internal/config/server.go:164`) sender-constrains CLI
credentials. A cookie session has no proof-of-possession, so shipping one silently exempts the browser —
the downgrade the switch exists to prevent.

**Decision: fail closed.** When `REQUIRE_DPOP=1`, console login is **unavailable** and the server says so
at startup. Session binding (non-extractable WebCrypto keypair, or DBSC) is a named later ticket, not an
assumption. Recorded in ADR-14 as a residual, not hidden.

### 2.3 What a compromised console session buys over a compromised CLI token

Stated because the design must not treat them as equivalent, and `docs/threat-model.md` "Compromised
administrator" needs rewriting **as part of this work**:

- Today a stolen bearer token is effectively **read-only** — every write handler 401s without a
  certificate. A session is write-capable by definition. That is a privilege escalation the design
  introduces, not a lateral move.
- The credential shares a process with hostile data: a browser rendering attacker-controlled filenames, log
  lines and DNS names all day.
- A certificate is not phishable; a session is. The threat model's bound moves from "as strong as the CA's
  issuance discipline" to "as strong as the IdP's phishing resistance plus the session implementation."
- **Aggregation**: one origin, one credential, reaching config, fleet-control, intents, legal-hold release
  and DSAR export.

---

## 3. Rendering untrusted data

Nearly everything the console displays is attacker-controlled: filenames, process arguments, log lines,
DNS names, HTTP headers, user agents.

- **One `<Untrusted>` component is the only path telemetry reaches the DOM.** An href scheme allowlist
  (`https`, `http`, `mailto`) is applied *inside* it, never at call sites — the pivot-menu-on-every-value
  requirement (§4.1) turns every telemetry string into a potential `href`, and `javascript:`/`data:` URIs
  are blocked by neither CSP `frame-ancestors` nor a no-inline-script policy.
- A tree-wide lint ban on `dangerouslySetInnerHTML`, in the same spirit as the no-bare-string rule.
- CSP: `default-src 'none'`, no inline script or style, plus `object-src 'none'`, `base-uri 'none'`,
  `form-action 'self'`, `frame-ancestors 'none'`.
- The named i18n residual — backend reason strings "shown verbatim" (§5) — routes through `<Untrusted>`
  like everything else.

**The four-eyes approval screen is hardened specifically** (it is the highest-value target in the UI):

- a **server-generated, closed-vocabulary summary** of the act (verb, subject count, blast radius, TTL)
  renders above the requester's free text;
- the requester's `reason` is visually quoted as untrusted and never interpolated into notification fields
  that routing depends on;
- the approve POST carries a server-issued one-time confirmation token bound to
  `(approval_id, requester, digest of the summary shown)`, so approving a stale or re-rendered row fails
  closed;
- clickjacking is blocked by `frame-ancestors 'none'` and the confirmation token.

---

## 4. Information architecture

### 4.1 The pivot spine (cross-cutting, not a page)

The roadmap names exactly five verbs — *pivot, search, compare hosts, replay, explain a block*. The spine
is what serves them:

- **Command palette (⌘K)** reaching any entity, host, incident or case in two keystrokes.
- **A global time range** that survives every pivot and lives in the URL.
- **Split-pane compare** — two hosts or two incidents side by side.
- **A pivot menu on every value in every table.**
- **Every view URL-addressable**, so an IR handoff is a pasted link.
- **Keyboard-first**, with the whole investigation loop completable without a mouse.

### 4.2 MVP console — five surfaces

1. **Incidents** — queue plus detail. Detail is the centrepiece: the cross-domain timeline (XDR-5) with
   the **three evidence states rendered visually distinct** (resolved / unresolved / derived), contributing
   alerts by domain, entity panel, recurrence chain, playbook run trace (ran / resumed / skipped),
   approvals, attributed lifecycle transitions, notification log. Cases fold in here. A health strip
   replaces a separate Overview page.
2. **Entity** — device⋈user: risk over time, related entities, alerts and events, posture and attestation
   history.
3. **Hunt** — one query surface over `/events`, `/logs`, `/search` and saved searches (SIEM-14, D426),
   including the field-level JSONB drill.
4. **Fleet** — agent inventory, plus the **enforcement/break-glass surface**: which agents are currently
   suppressed, since when, by whom, and until when. `INVARIANTS.md:131` — *"'How do I stop this?' is the
   question a CISO asks before 'what does it detect?'"*
5. **Explain a decision** — the thesis page. The Event→Classify→Policy→Decision→Enforce→Audit trace for one
   decision, which pack and rule won under the most-restrictive-wins lattice (ADR-5), and **Replay**: does
   current policy still produce this decision, and if not, what changed.

### 4.3 Deferred surfaces — on the roadmap, not gating

Each keeps its ticket ID so nothing reads as forgotten: standalone **Overview** dashboard, **Alerts** as a
first-class page, **Response** (playbook definitions, integration runners, notification routing),
**Evidence/ledger** browser with restore-drill history and the view-audit reader, **Configuration**
(schema-driven forms over `/config/schema`), **Administration** (roles, enroll tokens, feeds,
integrations, retention, DSAR), **Policy** (packs in force, lattice preview, simulation).

### 4.4 Design principles

- **Never render uncertainty as certainty.** A derived evidence link never looks like a resolved one.
- **Never invent data.** No client-side aggregate the server did not compute — an aggregate the UI invents
  cannot be audited.
- **Read-only by default**; every mutation shows what will be signed and audited before it happens.
- **Show the boundary.** SOAR-6 already reports metrics with the population they exclude; the console
  renders that rather than hiding it.
- **Degraded is a first-class state.** What the console shows when the leader lease moves (ADR-3), when
  NATS is down, or when it is talking to a follower is specified, not discovered.

---

## 5. The view audit — the console dilutes it, and must repair it

The original draft claimed console reads are "attributed and audited for free." **That was false.**
`RecordView` has four non-test call sites: `views.go:47` (`/view`), `timeline.go:197`, `dsar.go:127`,
`cases_http.go:126`. `/alerts`, `/search`, `/events`, `/logs`, `/incidents`, `/overdue`, `/subject`,
`/searches/run` record nothing.

`docs/threat-model.md:184` bounds the malicious-operator insider with *"VIEW AUDITING (D20/L1) — who LOOKED
is recorded."* A console makes the unaudited routes the *primary* read paths and issues orders of magnitude
more reads than a CLI, converting that adversary's task from "read one investigation and leave a row" into
"scroll the fleet and leave nothing." **That is a strict weakening of a documented trust boundary in
exchange for adopting a UI**, and it must be repaired in the same lane, not after.

- A per-route decision on what constitutes an evidence-bearing read, recorded **before** the response, with
  the filter stored as `subject_filter` (the schema already supports it).
- The residual stated for every route deliberately left unaudited.
- **`investigation_views` needs a retention window, a purge, and a DSAR path.** Migration
  `007_investigation_views.sql` has no TTL and appears in no purge query; it stores a *raw, deliberately
  non-pseudonymised* operator identity (`openspec/specs/operator-identity/spec.md:197`) plus a subject
  filter. A console makes it one of the largest tables in the database, full of employee-identifying data,
  outside the GDPR erasure machinery the product already ships (PLAT-8).
- Volume anomaly detection per viewer, so "scroll the fleet" is itself detectable.

---

## 6. Freshness — polling, not streaming

Correlation runs on a **clock**, leader-only (SOAR-2/D250), so incidents materialize on an interval.
Streaming would buy latency the backend does not produce.

It would also cost: a long-lived stream authorizes once at handshake, while `requireTier` deliberately
re-resolves the role **per request with no cache** — `operator_roles.go:26-32`: *"the revocation takes
effect within the cache TTL is the sentence that makes a security control untrustworthy."* A stream is an
unbounded, invisible cache whose TTL is the socket lifetime.

**Decision:** ETag / `If-None-Match` polling at 10–15s. `internal/nips/urlfeed.go` already speaks this
dialect as a client. **Residual, stated:** console freshness is bounded by the poll interval *and* the
correlation interval, and the second dominates.

Streaming stays on the roadmap as `API-9`, to be reconsidered against a **measured** requirement — and if
it lands, the stream loop must re-resolve the role on a tick, tear down on mismatch, and cap its lifetime
below the session idle timeout.

---

## 7. Internationalization

English ships. Language packs are added later.

- Every string through `react-i18next` with ICU (plurals, gender, nested selects).
- **Bundles are embedded and signed with the release**, not loaded from a mutable operator directory. An
  unsigned hot-loaded locale pack rewrites UI text — *including the four-eyes approval button label* —
  so whoever can write that directory turns "Approve containment of prod-db" into "Acknowledge alert" and
  the approver genuinely consents to a different act. `docs/threat-model.md:193` requires signatures on
  everything loaded before it is parsed. A signed, verified-before-parse overlay is a later ticket
  (`UI-19`); the unsigned overlay is **refused**.
- **Security-critical strings — approval confirmations and destructive-action labels — live in a
  non-overridable namespace embedded in the binary**, unreachable by any pack.
- `escapeValue` stays on; `<Trans>` interpolation of telemetry goes through `<Untrusted>` (§3).
- Two gates that stop single-locale i18n rotting: an ESLint rule failing CI on any bare user-visible string
  literal, and a **pseudolocale (`en-XA`)** render test proving extraction with no translator present.
- All dates, numbers, durations formatted client-side via `Intl` with a selectable timezone. **Never format
  on the server.**
- **Logical CSS properties from day one** (`margin-inline-start`, never `margin-left`) so RTL is a data
  change later rather than a rewrite.
- **Named residual:** backend-emitted reason strings — alert reasons, policy explanations, redirect targets
  — stay English and render verbatim. The alert reason is what the analyst actually reads, so the honest
  claim is *"the console chrome is localizable; the security narrative is not yet."* The forward path
  (message IDs + params at the emission point) is `I18N-2`, on the roadmap, not claimed as done.

---

## 8. Topology — its own lane, not a console page

Kept in full on the roadmap; sequenced **after** the console MVP because it serves none of the five
adoption verbs.

**Phase 1 — model (`TOPO-1`/`TOPO-2`).** Typed nodes: control-plane server · worker · gateway in one of
four modes (egress proxy, ZT access proxy, inline TPROXY, DNS sinkhole) · endpoint agent group · internal
service · external network · identity provider · broker · database · integration sink · site/zone.
Every node is **discovered** (bound to a real enrolled agent or gateway by canonical device identity,
IDENT-1/ADR-6) or **declared** (something OpenShield does not run). Edges are typed and typechecked:
`routes-traffic-to`, `protected-by`, `enrolls-with`, `publishes-to`, `authenticates-against`. Revisioned
like PLAT-5 config — author, diff, rollback, audited.

**Drift is the feature**, and it ships first and cheaply: declared-but-not-enrolled,
enrolled-but-not-declared, and gateways enforcing rules the topology does not declare. **This is a list on
the Fleet page and needs no canvas** — `TOPO-1` delivers it before `TOPO-2` draws anything.

**Phase 2 — compile (`TOPO-3`).** A pure function: graph → *proposed* gateway configuration plus catalogs,
with a validated per-node diff. Generates, never applies. Pure means directly testable.

**Phase 3 — apply (`TOPO-4`/`TOPO-5`), owner-gated.** Gateway config is deliberately **all bootstrap-scope,
node-local, with no database credentials** (D272), so apply cannot go through the config DB and needs a
signed fleet-wide channel. Three constraints that are the whole design:

1. **It must not become a second command channel.** `INVARIANTS.md:27` bounds a compromised control plane
   because *"there is no message meaning 'run this'"*. A configuration language is not a closed vocabulary,
   and configuration is where enforcement lives. **A compiled config that reduces enforcement coverage must
   be refused unless expressed as `ENFORCEMENT_DISABLE`** — computed by the compiler as a coverage
   invariant — so it inherits `fleetcontrol.go:22-35`'s mandatory four-eyes, monotonic sequence and TTL
   rather than routing around them. Otherwise "draw the gateway out of the path" disables the fleet
   silently, and "empty the feed catalog" stops it blocking known-bad while it reports healthy.
2. **Approval must be semantic.** Nobody approves a compiled routing diff by inspection. The approval
   screen shows *"prod-web loses inline inspection"*, never a field diff.
3. **Rollback must not flap.** Self-check is **locally observable only** (config parses, rules load,
   counters increment) and never depends on a network path an adversary shares — otherwise apply / rollback
   / retry is a sustained flap and every transition is a window of indeterminate ruleset. Rollback targets
   a **named, signed, known-good revision**, not "previous". Rate-limited per node, **fail-static** (keep
   last-good enforcing and raise an alert) rather than fail-flap. Every rollback is an audited event.

---

## 9. AI — a standalone, owner-gated proposal

**Removed from PLAT-1. Zero AI tickets gate the console.**

`grep -niE "\bLLM\b|\bAI\b|model provider"` over the roadmap, `README.md` and `ETHICS.md` returns nothing.
The repo's rule is explicit — *"ADR-0/-11 are **owner decisions**"* — and a Helm chart was **refused by
name** (D276). An LLM in a product whose pitch is reproducibility and air-gap-ability is a larger
positioning decision than that, and bundling it into PLAT-1 makes the console's scope unreviewable.

It sits beside NAC and VPN in 🔒 Parked with its design intact, so the ground is prepared and the decision
is the owner's.

### 9.1 The invariant, if it is ever taken up

**AI is never in the decision path.** It cannot classify, evaluate policy, decide or enforce. Any action it
proposes travels the existing signed Response-Intent seam with four-eyes, unchanged. This keeps the closed
action set (D14) and closed intent vocabulary bounding what reaches an endpoint, and preserves replay — an
LLM score is not reproducible, so `openshieldctl replay` would stop meaning anything if a model
participated in classification. **UEBA stays statistical for the same reason.**

### 9.2 What the security review broke, and what would have to hold

These are why this is a proposal and not a plan. Each defeats the draft's stated mitigation:

- **A cited claim is not a true claim.** Citations prove the referent exists, not that the prose describes
  it. An attacker who plants one filename — `approved-by-CHG-1042-security-signoff.xlsx` — gets a real
  evidence ID that resolves green, and a summary reads *"likely benign, authorized under CHG-1042
  [ev:7f2a]"*: fully cited, ledger-resolvable, false. No injection string, no schema violation, no
  behaviour change for a poisoned-corpus test to catch. **Required:** retrieval filters on `verified` and
  the trust label travels into the render (INV-4 already forbids counting unverified telemetry — the
  assistant would be the first component to launder it into an analyst-facing conclusion); a citation
  renders the evidence **verbatim and inline**, never a bare ID chip; the corpus test asserts the
  **rendered narrative**, not the model's tool calls.
- **"Retrieval scoped to the operator's tier" is not enforceable.** Tier is a *route* property; no
  evidence row carries one. A retriever reading tables re-implements the route map and drifts.
  **Required:** retrieval goes through the same HTTP handlers, as the calling operator, over loopback.
- **"Redacted before send" cites a capability that does not cover the data.** The existing pseudonymiser
  one-way-hashes a *subject identity* (`internal/gateway/identity/identity.go:85`); it does nothing to
  filenames, command lines, URLs, headers or external log bodies — exactly where credentials in process
  args and PII in document paths live. With a hosted provider that is a working exfiltration channel
  needing no compromise. **Required:** an allowlist **projection function** with a closed output schema —
  fields enumerated in code, everything else dropped, not scanned-and-redacted — shipped before any
  feature uses it, and hosted providers refusing to start without it.
- **A prompt hash is not an audit.** It cannot reconstruct what left the boundary or answer "what personal
  data was transferred." **Required:** store the projected payload under evidence retention and legal
  hold, or state plainly that AI calls are *logged, not auditable to the platform's standard*.
- **"AI output is never evidence" does not survive `POST /cases/note`.** Case notes flow into legal hold,
  DSAR and ITSM export, and nothing distinguishes a human conclusion from a pasted summary. **Required:**
  a distinct endpoint writing a provenance-bearing column enforced at the store, or the residual stated
  honestly instead of the property claimed.

### 9.3 Where it would help, ranked

Incident narrative → natural-language-to-structured-query for Hunt (shown as the structured query before it
runs, editable, never free-form SQL) → explain-a-decision in prose → triage suggestions → playbook draft
validated against the **closed** step registry → topology assistant → post-incident and DSAR drafting.

---

## 10. Assurance

- **Every guard names its mutation.** `INVARIANTS.md:12`: *"a row here is a claim backed by a
  demonstration, not by a comment."* No guard enters a ticket without the change that must make it fail.
- **Clicks-to-answer budgets are CI-gating** — the top eight analyst questions, asserted in Playwright.
- **Golden-response fixtures, not generated types.** Most handlers return anonymous `map[string]any`
  (`incidents.go:195`, `soar2.go`, `config_http.go`), so a Go→TS generator would silently degrade into
  "generate a few, hand-write the rest" — the half-maintained source of truth this project keeps being
  burned by. One recorded JSON fixture per route, asserted by the Go test *and* type-checked against the
  hand-written TS type, catches the same drift with nothing to rot.
- **Accessibility**: axe in CI, WCAG 2.2 AA, keyboard-only path through the whole investigation loop.
- **Reproducibility is a claim-validity gate, not a nice-to-have.** `internal/release/release_test.go:161`
  *tests* that builds are byte-identical, and `threat-model.md:195` says reproducible builds are what make
  a release signature mean anything. Embedding bundler output puts a non-deterministic input inside that
  digest. Required: pinned-digest, **network-less** container build; `SOURCE_DATE_EPOCH`; a byte-identical
  rebuild check that **fails the release**; Node/pnpm pinned in the manifest beside the Go toolchain.
- **Supply chain, judged the way D276 judged goreleaser** — which was refused as *"a dependency taken for
  its own sake."* Every direct dependency gets one sentence saying what working code it replaces or what
  property it buys; the budget is a **number** enforced in CI (transitive count and install size). Note
  `--ignore-scripts` is *not* the control here: `vite.config.ts` and its plugin import closure execute with
  full filesystem and network access during `pnpm build` — on the machine holding the signing key. That
  import closure is privileged code and reviewed as such.
- **JS SBOM from the lockfile, fed into `BuildSBOM`** so the manifest signature covers it. Today
  `internal/release/sbom.go:55` derives from `debug/buildinfo` — the linker's module graph — and would
  describe zero npm packages.

---

## 10a. Enterprise completeness

A third review judged the plan against what a 2026 buyer asks for on day one — Splunk ES, Defender XDR,
Falcon, Elastic Security, Wazuh as the comparison set. The absences it found are folded into Lane F as
`CONSOLE-25`…`-39`. The ones that changed the MVP:

- **Step-up re-authentication** on `CONTAIN`, `ENFORCEMENT_DISABLE`, legal-hold release, DSAR export and
  case closure (`CONSOLE-25`) — the compensating control for the privilege escalation §2.3 admits the
  console introduces, and it binds to the confirmation token §3 already issues. The plan had no mention of
  MFA at all, not even that it is delegated to the IdP.
- **The queue is not a worklist** (`CONSOLE-26`): no assignment, no ownership, no shift handover, and
  acknowledging a 200-incident phishing wave one at a time. *Assignment is workflow, not measurement* —
  stated explicitly so it is not mistaken for the per-analyst aggregation SOAR-6 deliberately refuses as
  workforce surveillance.
- **No suppression and no closure disposition** (`CONSOLE-27`) — the tuning loop. Its absence is the most
  common reason a security-tool pilot is judged "too noisy" in week three, and the disposition enum is
  nearly free during `CONSOLE-4` and a backfill afterwards.
- **No export** (`CONSOLE-28`), which is also the sharpest instance of §5's concern: a bulk export *is*
  "scroll the fleet and leave nothing", so it is view-audited with row count and filter.
- **No session inventory or revoke-all** (`CONSOLE-29`), and no statement that SCIM deprovisioning kills a
  live cookie session — per-request role resolution covers authorization, not session existence.

And the one that changed `CONSOLE-1`: it is already rewriting the principal model, so a **machine principal
that can never satisfy four-eyes**, a **scope seam** for later tenancy, and **splitting `admin` from
`privacy-officer`** are small inside it and large after it. Deferred but recorded: multi-tenancy
(`CONSOLE-37`, owner call), custom roles (`-30`), reporting and compliance evidence packs (`-31`), audit
egress to the customer's SIEM (`-32` — the product ingests four log formats and emits none), onboarding and
self-diagnosis (`-33`), OpenAPI (`-34`), shared views and watchlists (`-35`), SLA timers (`-36`), VPAT and
browser matrix (`-38`).

**Three cuts to make room, all sequencing rather than refusal:** split-pane compare → `CONSOLE-39`; the
standalone Entity page folds into the incident detail's entity panel (`CONSOLE-9`'s API still ships on
schedule); and `CONSOLE-13` i18n moves to Phase 3, keeping only logical CSS properties and the
no-bare-string lint in Phase 0 — because the plan's own residual concedes alert reasons stay English until
`I18N-2`, so a Phase-2 i18n ships translated chrome above an English security narrative. **Multilingual
support itself is not in question; only its position in the queue, and the owner may put it back.**

## 11. Review record

**Retracted.** The draft claimed `/incidents/recurrences` was gated on `RoleAgent`. It is
`requireTier(RoleAnalyst, opRead)` at `enroll_http.go:122` and always was. The draft also claimed console
reads are view-audited "for free" (§5 corrects it) and was written against D419 while HEAD was D426.

**Disputed and not accepted.** One reviewer argued for cutting `react-i18next`/ICU entirely as YAGNI for a
single English locale, citing `openspec/config.yaml`'s *"ambition is the failure mode."* The owner
requires multilingual support, so the framework, ICU, logical CSS and the lint gate are kept; only the
unsigned runtime overlay is refused (§7). A second reviewer reported uncommitted saved-search WIP carrying
the unmounted-route defect — false at HEAD: SIEM-14 shipped as D426 and is correctly mounted
(`enroll_http.go:107-110`).

**Accepted and folded in.** The identity-threading blocker and its four-eyes trap (§1.1–1.2), the route
table as data (§1.4), the view-audit dilution and `investigation_views` retention (§5), keyset pagination
and the `/health` and break-glass gaps (§1.3, §4.2), polling over streaming (§6), golden fixtures over
codegen (§10), reproducibility and the `vite.config.ts` execution surface (§10), the untrusted-render
component and approval-screen hardening (§3), DPoP fail-closed (§2.2), the OAuth-client separation and
audience confusion (§2.1), AI extracted to owner-gated with §9.2's specific breaks, and topology's coverage
invariant, semantic approval and fail-static rollback (§8).

---

## 12. Sequencing

**Superseded — do not sequence from this document.** This section originally used `API-0`/`UI-0`/`UI-1`…
identifiers that no longer exist, listed Entity as an MVP surface after §10 had folded it away, and put
i18n in Phase 2 after §10 had moved it to Phase 3. A sequencing plan that contradicts its own document two
sections earlier is precisely the stale-source-of-truth failure this project keeps finding.

**The roadmap is the single source for sequencing**: `docs/architecture-roadmap.md`, *Lane F · Console*
(`CONSOLE-1`…`-52`, phases 0–3) and *Lane G · Topology* (`TOPO-1`…`-8`), with `PLAT-5c`/`-5d`/`-5e` in
Lane D. The design rationale in §1–§11 above stands; only the ordering moved.

## 13. ADRs proposed

- **ADR-13** — frontend toolchain and embedding: React/TS/Vite, `embed.FS`, same origin, no CDN, Node-free
  Go build, reproducible bundle as a release gate.
- **ADR-14** — one canonical operator principal across credentials; the console adds authentication only;
  four-eyes compares account, not principal string; `REQUIRE_DPOP=1` refuses console login.
- **ADR-15** — topology is declarative and compiled; it applies only over a signed channel, and any
  coverage-reducing change must be expressed as `ENFORCEMENT_DISABLE`.
- **ADR-16** *(owner-gated, with the AI lane)* — AI is an assistant over evidence and never a decider;
  retrieval goes through the operator's own authorization path; egress is an allowlist projection; AI
  output is never evidence.
