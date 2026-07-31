# OpenShield Console — UX specification

**Date:** 2026-07-31 · **Companion to:** `2026-07-31-console-plat1-design.md` (architecture, tickets, ADRs)
**Scope:** design direction, design system, every page, every state, every workflow, the settings IA, and
the permission matrix. This is the document a designer and a frontend engineer build from.

---

## 1. Design direction

### 1.1 What this interface is for

A security analyst on hour nine of a twelve-hour shift, in a dim room, needs to answer *"is this real, and
what do I do about it?"* — and then needs to prove to somebody else, possibly a regulator, that the answer
was right. Two audiences, one surface: the analyst who lives in it daily, and the auditor who visits it
once and must be able to trust it.

### 1.2 The concept: **an instrument, not a dashboard**

The product's crown jewel is a forward-secure hash-chained evidence ledger, and its thesis is that every
decision is explainable and reproducible. So the console reads as a **forensic instrument** — a measuring
device and a court record — rather than a marketing dashboard.

Concretely, that means:

- **Evidence is typographically distinct from interpretation.** A quoted log line, a filename, a hash never
  wears the same type as the product's own prose about it. The analyst must always be able to see where the
  machine's words end and the attacker's begin.
- **Nothing is decorative.** No illustration, no gradient mesh, no hero imagery. Every pixel of colour and
  every rule carries meaning. In a room where a red thing means "wake someone up", decorative red is a
  safety defect.
- **Density is a feature.** A SOC analyst wants forty rows, not twelve. Whitespace is spent on *separating
  meaning*, never on breathing room for its own sake.
- **The chain is visible.** Sequence, ordering and linkage are the product's substance, so the visual
  language uses hairline connectors, ordinal markers and chain motifs where other products would use cards.

### 1.3 The one thing people remember

**The incident timeline.** A vertical chain where each contributing alert is a link, drawn across domain
lanes (endpoint / network / identity), where **the tie to evidence is rendered as a physical state of the
link** — welded, open, or inferred — so an analyst can see at a glance which parts of the story are proven
and which are reconstruction. Nobody else renders doubt. This product must, because XDR-5 already computes
it and hiding it would be the dishonest choice.

### 1.4 Dark-first, and why

The default theme is dark, because SOCs run dark and this is where the product is used. Light is a
first-class alternative, not an afterthought, because auditors, executives and anyone exporting to PDF work
in light. Both themes are held to the same contrast standard; neither is a filter over the other.

---

## 2. Design system

### 2.1 Typography

**IBM Plex Sans** (UI) + **IBM Plex Mono** (evidence, identifiers, numerics) + **IBM Plex Sans Condensed**
(dense table headers only).

This is a functional choice before an aesthetic one:

- The Plex superfamily has the **broadest script coverage of any open-source UI superfamily** — Arabic,
  Hebrew, Devanagari, Thai, JP, KR, SC/TC — which is what makes the multilingual requirement and RTL
  achievable rather than aspirational. A typeface that cannot render the locale is an i18n bug.
- It has engineering provenance and real character without being the current default (it is not Inter, not
  Roboto, not a system stack).
- Plex Mono's tabular figures let hashes, IDs and timestamps be **compared by eye down a column**, which is
  the single most common act in forensic review.

**The evidence rule.** Everything that originated outside OpenShield — log lines, filenames, process
arguments, DNS names, hashes, user agents, requester free text — is set in **Plex Mono**, on a subtly
inset background, with a left hairline. Everything OpenShield itself says is Plex Sans. This is a security
control expressed as typography: it makes attacker-supplied text visually unable to impersonate product
copy.

| Role | Face | Size / line | Notes |
|---|---|---|---|
| Page title | Plex Sans 600 | 20 / 28 | one per view, never repeated in breadcrumb |
| Section | Plex Sans 600 | 13 / 20 | uppercase, +0.08em tracking |
| Body | Plex Sans 400 | 13 / 20 | the density default |
| Table cell | Plex Sans 400 | 13 / 18 | tabular numerals on |
| Table header | Plex Sans Condensed 500 | 11 / 16 | uppercase, +0.06em |
| Evidence / ID | Plex Mono 400 | 12 / 18 | the untrusted-text face |
| Metric numeral | Plex Mono 300 | 28 / 32 | tabular, never bold |
| Help / residual | Plex Sans 400 | 12 / 18 | de-emphasised ink |

Minimum size anywhere is 11px, and only for uppercase table headers with tracking. No 10px.

### 2.2 Colour

**One rule governs everything: saturated colour means severity, and nothing else means severity.** Every
other affordance — selection, focus, links, actions — uses the neutral ramp plus a single cool accent. If
navigation were blue and alerts were also blue, the eye would stop treating colour as signal.

**Neutrals — warm-shifted, not pure grey.** Pure `#000`/`#fff` are banned: pure black loses subpixel
rendering on dark and causes halation for astigmatic readers on long shifts, and pure white on light is
glare at 3am.

```
ink-950  #0B0C0E   canvas (dark)        ink-050  #FAFAF8  canvas (light)
ink-900  #121417   surface              ink-100  #F2F2EF  surface
ink-850  #191C20   raised / row hover   ink-200  #E4E4E0  raised
ink-700  #2A2E34   hairline             ink-300  #CFCFCA  hairline
ink-500  #6B7280   de-emphasised text   ink-500  #6B7280  de-emphasised text
ink-200  #D6D8DC   body text (dark)     ink-900  #16181B  body text (light)
ink-050  #F5F6F7   emphasis text        ink-950  #0B0C0E  emphasis text
```

**Severity — sequential, colourblind-safe, and redundantly encoded.** The ramp runs cool→warm by
*luminance as well as hue*, so it survives deuteranopia, protanopia and greyscale printing. Every severity
chip carries a **glyph and a text label**, never colour alone.

| Severity | Dark | Light | Glyph | Rule |
|---|---|---|---|---|
| Critical | `#FF6B5A` | `#C0392B` | ▲ filled | the only colour permitted to animate |
| High | `#FF9F45` | `#B25E00` | ▲ open | |
| Medium | `#E3C567` | `#8A6D1F` | ■ | |
| Low | `#7FB3D5` | `#2C6E9B` | ● | |
| Info | `ink-500` | `ink-500` | — | neutral by design |

**Accent — one, cool, and structural:** `#5EC8D8` (dark) / `#0E7C8C` (light). Focus rings, selection,
links, active nav. Never used for status.

**Evidence state is NOT colour.** Resolved / unresolved / derived are encoded as **link geometry** on the
timeline and **border treatment** on chips — solid, hollow, dashed — because they must remain legible in
greyscale (evidence exports get printed into legal records) and must never be confused with severity.

```
resolved    ●━━━━  solid link, filled node      "verified against the ledger"
unresolved  ○┅┅┅┅  hollow node, dotted link     "referenced, not found"
derived     ◐┄┄┄┄  half node, dashed link       "inferred, not directly evidenced"
```

**Semantic non-severity states** use the neutral ramp with iconography: `degraded` (hatched fill),
`suppressed` (strikethrough rule), `stale` (reduced opacity + timestamp badge).

### 2.3 Space, grid, density

4px base unit. Row height 32px default / 28px compact / 40px comfortable. Content max-width is **not**
constrained — this is an instrument; a 21:9 monitor should show more columns, not more margin. Tables get a
sticky header and a sticky first column.

Hairlines (1px `ink-700`) separate rows, not shadows or cards. **Cards are used exactly once** — the
approval confirmation dialog — so that the one moment a card appears, it means "stop and read this".

### 2.4 Motion

Motion earns its place only where it communicates. Default duration 120ms, `cubic-bezier(.2,0,0,1)`.

- **Permitted:** row expansion, panel slide, timeline link draw-in on first load (staggered 20ms per link,
  once, never on refresh), the severity-critical chip's 2s pulse.
- **Banned:** page transitions, skeleton shimmer that moves, anything on data refresh (a moving number is an
  unreadable number), parallax, scroll-triggered reveals.
- `prefers-reduced-motion: reduce` removes all of it including the pulse, replacing the pulse with a static
  double border.

### 2.5 Iconography

A single 16px line set at 1.5px stroke, drawn in-house — 24 glyphs, no icon library dependency (the
dependency budget in `CONSOLE-2` is real). Icons **never appear alone** on an interactive control; every
icon button carries a visible label or is inside a labelled group. Icon-only toolbars are how a console
becomes unlearnable.

---

## 3. Component inventory

The whole console is built from 26 components. Anything not on this list requires a decision.

**Primitives** — Button (primary/secondary/ghost/destructive), Input, Select, Combobox, Checkbox, Radio,
Toggle, DateTimeRange, Tag, Chip, Tooltip, Popover, Dialog, Toast, Spinner, ProgressBar.

**Domain** — `SeverityChip`, `EvidenceState`, `<Untrusted>` (the only path telemetry reaches the DOM, §2.1
+ href allowlist), `PrincipalChip` (human / machine / revoked, with tier), `TimeAgo` (absolute on hover,
locale-formatted), `EntityRef` (pivot-menu-bearing), `LedgerRef` (verify state + copyable hash),
`DataGrid` (virtualized, keyset-paged, column-pinning, selection), `TimelineChain`, `StateView` (§4).

---

## 4. The state catalogue

**Every view must specify all nine.** This is the section most plans omit and most consoles fail on. A view
that has not defined these is not designed.

| State | Requirement |
|---|---|
| **Loading (first)** | Static skeleton matching final layout. No shimmer. If >400ms, add a cancellable label. |
| **Loading (refresh)** | Content stays, a hairline progress bar appears at the top of the region. Numbers never blank. |
| **Empty (no data yet)** | Distinguish from broken: state *why* it's empty and give the next action. "No incidents in the last 24h" + widen-range button. |
| **Empty (never configured)** | The onboarding case (`CONSOLE-33`). "0 agents enrolled" + the actual enroll command, copyable. |
| **Filtered to nothing** | Show the active filters and a one-click clear. Never the same screen as "no data". |
| **Error** | What failed, what still works, what to do. Retry. Never a raw status code alone; never "something went wrong". |
| **Degraded** | *First-class here.* Leader lease moved, broker down, ingest behind, schema skew, follower node. A persistent banner naming the impairment and **what the data on screen therefore is** — e.g. "correlation paused 4m ago; incidents shown are current, new ones are not being formed." |
| **Stale** | Poll failed but cached data is shown. Timestamp badge goes amber, banner states last-successful time. Never silently show old data as current. |
| **Forbidden** | Tier insufficient. Name the tier required and who grants it. Distinguish *revoked* from *never had it* — the API already does (`views.go`), and they send a person to different places. |

---

## 5. Global chrome and the pivot spine

```
┌────────────────────────────────────────────────────────────────────────────┐
│ ▸ OPENSHIELD   [⌘K search or jump…]        ⟨ Last 24 hours ▾ ⟩   ◐  ⚙  ☺  │  40px
├──────┬─────────────────────────────────────────────────────────────────────┤
│      │  ‹ degraded / stale banner, only when true ›                        │
│ nav  │                                                                      │
│ 200  │  page title                                    [ page actions ]      │
│ px   │  ─────────────────────────────────────────────────────────────────   │
│      │                                                                      │
│ ◧    │  content                                                             │
│ ◨    │                                                                      │
└──────┴─────────────────────────────────────────────────────────────────────┘
```

**Left rail (200px, collapsible to 48px):** Incidents · Hunt · Fleet · Entities* · Evidence* ·
Settings · Admin*. Starred items appear by tier. A live count badge on Incidents (unassigned, mine) and on
Approvals-pending — those are the only two badges permitted, because a badge on everything is a badge on
nothing.

**Command palette (⌘K)** — the spine. Four modes in one input, disambiguated by prefix:

| Prefix | Mode | Example |
|---|---|---|
| *(none)* | jump to entity / host / incident / case | `web-prod-04` |
| `>` | run a command | `> assign to me`, `> suppress this rule` |
| `?` | ask the field grammar | `? severity` lists valid values |
| `#` | go to a saved or shared view | `#team-triage` |

Recency-ranked, keyboard-only, and **it is the fastest path to every destination** — measured, in the
clicks-to-answer budgets (§7).

**Global time range** — persists across every pivot, lives in the URL, presets plus absolute, and shows the
*resolved* absolute window on hover so "last 24 hours" is never ambiguous in a handover.

**The pivot menu** — on every value in every table, opened by click or `→`:

```
  10.0.4.19
  ─────────────────────────
  Filter to this            ⏎
  Exclude this              ⌥⏎
  ─────────────────────────
  Show entity               e
  Events ±15 min            t
  All alerts for this       a
  ─────────────────────────
  Copy value                ⌘C
  Add to watchlist          w
```

**Keyboard map** — `j`/`k` row, `⏎` open, `x` select, `⌘A` select page, `/` filter, `g` then `i|h|f|e|s`
navigate, `[`/`]` prev/next in a result set *without returning to the list* (the single biggest triage
accelerator), `.` open pivot menu, `?` shortcuts, `Esc` back out one level.

---

## 6. Page specifications

### 6.1 Incidents — queue

**Purpose:** the shift's worklist. Not a list of everything; a list of what *this analyst* should do next.

```
Incidents                                    [ Bulk ▾ ]  [ Columns ]  [ Save view ]
Mine (4)   Unassigned (17)   All open (39)   Closed        ← tabs, not filters
─────────────────────────────────────────────────────────────────────────────────
□ SEV   ID      TITLE                     ENTITY        DOMAINS   SLA     ASSIGNEE  AGE
□ ▲ Cri INC-402 Credential access → exfil  ▣ mia@ / L14  ⬢⬡⬢      ⏱ 04:12  —        18m
□ ▲ Hig INC-399 Canary files modified      ▣ web-prod-04 ⬢⬡⬡      ⏱ 41:07  you      2h
□ ■ Med INC-388 Beaconing, unclassified    ▣ 10.0.4.19   ⬡⬢⬡      —        j.reyes  6h
```

- **DOMAINS** is a three-cell glyph strip (endpoint / network / identity), filled where that domain
  contributed. Cross-domain incidents are the product's whole claim, so they must be identifiable
  *without reading*.
- **SLA** is a countdown that turns amber at 25% remaining and critical at breach (`CONSOLE-36`). Absent
  where no target applies — blank, never `--`.
- Row click opens detail; `[`/`]` moves between incidents inside detail without returning here.
- Selection enables the bulk bar; **bulk containment is refused as a whole** if it would exceed the
  blast-radius ceiling, with the count that exceeded it named.

**States:** empty-never-configured routes to onboarding; degraded shows "correlation paused" and marks the
list as *not forming new incidents*; forbidden is unreachable (analyst is the floor).

### 6.2 Incidents — detail (the centrepiece)

Three columns: **chain** (fixed 380px) · **evidence** (fluid) · **response** (fixed 320px).

```
INC-402  Credential access → exfiltration           ▲ Critical    open ▾   [Assign ▾]
mia@corp.example ⋈ LAPTOP-L14 · first seen 18m ago · recurrence #3 of this chain
───────────────────────────────────────────────────────────────────────────────────
 CHAIN                       │ EVIDENCE                    │ RESPONSE
                             │                             │
 ⬡ identity      09:14:02    │  Selected: link 2 of 5      │ ▸ Playbook: cred-access
 ●━ impossible travel        │                             │   ✓ enrich observables
 ┃  resolved  ev:7f2a1c ⧉    │  ┌ agent · execaudit ─────┐ │   ✓ open case CASE-88
 ┃                           │  │ /usr/bin/curl           │ │   ⏸ contain  ← awaiting
 ⬢ endpoint      09:16:44    │  │ -sk https://198.51…/x   │ │      approval (4-eyes)
 ●━ credential dump          │  │ uid=1004 ppid=2210      │ │
 ┃  resolved  ev:9b02de ⧉    │  └─────────────────────────┘ │ ▸ Approvals
 ┃                           │   Plex Mono, inset, hairline │   ⧗ CONTAIN mia@
 ⬢ endpoint      09:21:10    │   = originated outside       │     requested by you
 ◐┄ suspicious exec          │                             │     ⚠ you cannot approve
 ┃  derived — inferred from  │  ledger  ⛓ verified          │     your own request
 ┃  pid reuse, not evidenced │  chain position 44,192      │
 ┃                           │  anchor 2026-07-31T08:00Z   │ ▸ Notifications (2)
 ⬡ network       09:24:57    │  [ Verify chain ]           │ ▸ Case CASE-88
 ○┅ exfil to 198.51.100.24   │                             │ ▸ Ticket INC-2291 ↗
    unresolved — referenced, │                             │
    evidence not found       │                             │ [ Close incident… ]
```

**The three link states are the design's load-bearing element.** A derived link is never mistakable for a
resolved one — different node fill, different stroke pattern, and an explicit sentence saying what it means.
The product computes this honestly (XDR-5); the UI's job is to refuse to smooth it over.

- The **ledger panel** shows chain position and last anchor, with a `Verify chain` action running a real
  verification and reporting the result — the crown jewel made visible rather than asserted.
- **Every evidence block is `<Untrusted>`**: Plex Mono, inset, left hairline, no link auto-detection beyond
  the scheme allowlist.
- The response column shows the playbook trace with per-step state including **resumed** and **skipped**,
  because SOAR-4 resumes across restart and an invisible resume looks like a duplicate.
- **Four-eyes is stated inline**, at the moment it matters: if you requested it, the panel says you cannot
  approve it, before you try.

**Clicks-to-answer:** queue → this view → understanding what happened = **1 click**. Everything above is on
one screen.

### 6.3 Hunt

Two-pane: query builder above, results below, with a saved/shared view rail.

- The query is **structured and visible** — field, operator, value chips — with a raw text mode that
  compiles to the same structure. Never a free-text box that hides what it will run.
- `? field` in the palette lists valid values for a field, sourced from the schema, so an analyst never
  guesses at an enum.
- Results are one grid over events, external logs and alerts with a **source column**, keyset-paged,
  virtualized. The JSONB field drill (SIEM-4) renders nested attacker-supplied keys through `<Untrusted>`.
- **Export** (`CONSOLE-28`) states the row count and that the export is view-audited, *before* it runs.
- Save view → personal; share view → team, with owner shown (`CONSOLE-35`).

### 6.4 Fleet

Grid of agents plus a **posture rail**. Columns: identity, platform, version, last seen, attestation
verdict + TTL, posture, enforcement mode, spool depth.

- **The break-glass surface lives here** (`CONSOLE-8`), and it is deliberately prominent rather than buried
  in settings: which agents are enforcement-suppressed, since when, by whom, until when, and a countdown to
  automatic restoration. `INVARIANTS.md` is explicit that "how do I stop this?" precedes "what does it
  detect?" — so the answer is one click from the top-level nav, not three.
- Attestation failures and stale attestations are a filter chip, not a buried column value.
- Drift from the topology model (`TOPO-1`) surfaces here as two counts — declared-not-enrolled and
  enrolled-not-declared — long before any canvas exists.

### 6.5 Explain a decision

Reachable from any decision, alert or event. A single-column narrative, wide margins — **the only
low-density page in the console**, because its audience includes people who do not use the product daily.

```
Why was this blocked?
─────────────────────────────────────────────────────
 EVENT       file write · /home/mia/export.csv · 09:31:02
     ↓
 CLASSIFY    EDM match · customer-pii-v4 · confidence 0.91
             ↳ 3 of 4 required cells matched
     ↓
 POLICY      bundle pii-baseline+pci-dss@v12
             ↳ pci-dss raised ALERT → BLOCK  ← the rule that won
             ↳ lattice: most-restrictive-wins
     ↓
 DECISION    BLOCK · confidence 0.91 · intent none
     ↓
 ENFORCE     write refused at fanotify · 4ms
     ↓
 AUDIT       ledger ⛓ verified · position 44,102

 [ Replay against current policy ]
 ─────────────────────────────────────────────────
 ✓ Current policy produces the same decision.
   Bundle has changed since (v12 → v14); the change did not affect this path.
```

**Replay is the thesis.** When the replayed decision *differs*, the page shows both and diffs the rule
path — that is the single most persuasive screen in the product, and it is why this page is in the MVP.

### 6.6 Tuning — how false positives are actually handled

**The scale question.** 100 endpoints producing thousands of events a day is not a data-volume problem —
correlation and dedup already collapse that into tens of incidents. It is a *trust* problem: if week three
produces forty alerts a day and thirty are noise, analysts stop reading the queue, and the product is dead
regardless of detection quality. **Tuning is not an admin convenience; it is the surface that decides
whether the console gets used at all.** It belongs in the MVP.

**What blocks it.** `unified_alerts` carries `domain` and `dedup_key` but **no stable rule identity**, and
`dedup_key`'s format is documented as a projection detail rather than a contract. Every question below —
"which rule is noisiest", "suppress *this rule* on *these hosts*", "what is this detector's FP rate" — needs
a stable `rule_id`. That is `CONSOLE-40`, and it gates the rest.

**The three-layer model**, because "suppression" conflates three different acts with different risks:

| Layer | What it does | Where it lives | Risk |
|---|---|---|---|
| **Disposition** | labels an alert/incident already raised — true positive / false positive / benign-authorized / duplicate | alert record | none; it is a fact about the past |
| **Exception** | stops *matching future events* from raising an alert, scoped and expiring | policy primitive (already sanctioned) | **reduces coverage** — audited, attributed, expiring, reviewable |
| **Threshold** | changes a detector's sensitivity fleet-wide | dynamic config | broad; a config revision with diff and rollback |

An operator reaching for "make this stop" is offered the **narrowest** layer that would work, with the
broader ones one click further away. Presenting them as equals is how a console ends up with a detector
silently disabled six months ago by somebody who left.

**The tuning flow, from an alert (4 clicks, workflow 5 in §7):**

```
Alert ▸ ⋯ ▸ Not a true positive
─────────────────────────────────────────────────────────────
 Disposition   ( ) True positive
               (•) False positive        ← selecting FP offers the next step
               ( ) Benign but authorized
               ( ) Duplicate of …

 ☑ Also stop this from alerting again

 SCOPE  — narrowest first, prefilled from this alert
   (•) This rule, on this host              → est. 31 of last 30d
   ( ) This rule, on this host group (12)   → est. 214 of last 30d
   ( ) This rule, everywhere                → est. 1,847 of last 30d  ⚠
   ( ) This rule + this exact path pattern  → est. 28 of last 30d

 EXPIRES  ( ) 7 days  (•) 30 days  ( ) 90 days  ( ) never ⚠ requires admin
 REASON   [ required, free text ]

 ⓘ This exception would have suppressed 31 alerts in the last 30 days,
   including 2 that were dispositioned TRUE POSITIVE.        ← the guard
   [ Review those 2 ]
─────────────────────────────────────────────────────────────
                                        [ Cancel ]  [ Create exception ]
```

**The line that makes this safe is the preview**, and specifically the second sentence of it: an exception
is dry-run against history *before* it exists, and if it would have suppressed anything an analyst called a
true positive, that is surfaced and countable. Tuning blind is how real detections get muted. The estimate
is computed server-side over the retention window, not in the browser.

**Never-expiring exceptions require the admin tier and a separate confirmation.** Default TTL is 30 days,
and expiry **restores detection** — the same shape as the intent TTLs the product already uses. An
exception that quietly became permanent is indistinguishable from a detector that was never written.

**Detector health** — the page that tells you whether tuning is working:

```
Detector health · last 30 days                        [ Domain ▾ ] [ Export ]
──────────────────────────────────────────────────────────────────────────────
RULE                        DOMAIN   FIRED   FP%   DISPOSITIONED  EXCEPTIONS  TREND
hips.canary.modified        endpoint  1,847  94%   612 of 1,847   3 active    ▁▃▇▇▅▂▁
dlp.edm.customer-pii-v4     endpoint    412  11%   380 of 412     0           ▃▃▄▃▃▄▃
nips.ioc.sni-match          network     208   3%   201 of 208     1 active    ▂▂▃▂▂▂▂
ueba.peer.deviation         identity     64  38%    22 of 64      0      ⚠ low coverage
```

- **FP% is computed only over dispositioned alerts**, and the `DISPOSITIONED` column shows the population
  it excludes — the same honesty SOAR-6 already applies to MTTA/MTTR. A rule with 12 of 1,800 dispositioned
  gets its percentage rendered de-emphasised with the sample size, never as a confident number.
- Rules sorted by *noise contribution*, not raw count: `fired × FP%`.
- The trend sparkline is **annotated with tuning events**, so "did that exception help" is visible rather
  than inferred.
- `⚠ low coverage` marks rules whose disposition rate is too low to say anything — an invitation to
  disposition, not a verdict.

**Exception register** — every active exception, its scope, author, reason, age, expiry countdown,
**suppressed-count since creation**, and a review queue for those expiring in 7 days. A suppressed count of
zero after 30 days means the exception is doing nothing and should be deleted; a suppressed count in the
thousands means the underlying detection needs fixing rather than muting. Both are visible here and nowhere
else.

**Learning mode.** A new deployment sets a per-domain observation window during which detections are
raised but not enforced and not paged, with a banner naming the end date and a one-click "promote to
enforcing". The UEBA baselines already persist and prune; this exposes the same idea for the rest and
prevents the week-one alert storm that kills pilots.

**At scale, the queue shows work, not events.** Alerts group by `dedup_key` with an occurrence count and a
sparkline; incidents group alerts; the default queue view is incidents. A thousand events becomes forty
alerts becomes six incidents. The raw stream stays reachable in Hunt for anyone who wants it — but the
default surface is the one that reflects how much work there actually is.

### 6.7 Zero Trust access — who may reach what

**This was missing, and the roadmap already said it would be needed:** `ZT-5 · Policy admin + session
recording — new work · L. Ties to the UI (PLAT-1).` The access proxy today is configured by
`OPENSHIELD_ACCESS_CATALOG` (an explicit allow-list of internal services, `internal/gateway/catalog.go:16`)
and `OPENSHIELD_ACCESS_POLICY` (a **Rego module**, default-deny, operator-authored,
`cmd/openshield-gateway/main.go:349-364`). Both are files. Neither has a UI, and the question every
administrator asks — *"who can reach the production database?"* — is answerable today only by reading Rego.

Four tabs.

**① Services** — the catalog. Name, kind (**HTTP reverse-proxied** vs **TCP CONNECT tunnel**, ZT-9/D427 —
and the UI must keep them distinct because the code deliberately refuses to interchange them), upstream,
which gateway fronts it, and the count of principals who may reach it. Adding a service is adding a row to
an allow-list, and the UI says so: *"services not listed here are refused, never forwarded."*

**② Access — the effective-access matrix.** The centrepiece, and the reason this page exists:

```
                        prod-db   billing   wiki   grafana   ssh-bastion
                        (tcp)     (http)    (http) (http)    (tcp)
─────────────────────────────────────────────────────────────────────────
 group: platform-eng      ●         ●         ●      ●          ●
 group: finance           ○         ●         ●      ○          ○
 group: contractors       ○         ○         ●      ○          ○
 mia@corp.example         ●*        ●         ●      ●          ○
 svc: backup-runner       ●         ○         ○      ○          ○
─────────────────────────────────────────────────────────────────────────
 ● allowed   ○ denied   * conditional — requires attested device, posture pass
```

- **Reads both directions**: pick a service → who reaches it; pick a person → what they reach. Both are the
  same question and both get asked, so neither is a filter on the other.
- **Every cell is explainable.** Click it and get the same Event→Policy→Decision trace as §6.5, showing
  which Rego rule allowed or denied and what conditions attached. An access matrix that cannot show its
  reasoning is a diagram, not a control.
- **Conditions are visible in the cell**, not hidden behind it — device attestation required, posture
  threshold, time window. A `*` that needs a hover to decode is a `*` nobody reads.
- **Drift**: rows where the catalog and the policy disagree — a service nobody can reach, or a policy rule
  naming a service not in the catalog — surface as warnings. Both are common and both are silent today.

**③ Policy.** Rego is the source of truth and **the console never becomes a second authoring model that
drifts from it** — that is exactly the failure this project keeps finding. So: the editor is the real
module, with syntax highlighting, a **dry-run evaluator** (pick a principal, a device posture and a
service; see the decision and the rule path), and a **diff + four-eyes on save**, because an access policy
change is a change to who can reach production. A guided builder emits Rego into the same module and shows
what it wrote — it never maintains a parallel representation.

**④ Sessions** (ZT-5). Active sessions: principal, device, service, started, bytes, source. Terminate one
or all for a principal — the thing an IR lead needs at 2am and currently cannot do from anywhere. Session
*recording* is a separate decision with a privacy weight the product should not take lightly: it is listed
here as owner-gated, with the DPIA implication named, not assumed.

**Device requirements** are shown as an attribute of access, not a separate page: a service can require an
attested device (the full ZT-1 chain), a posture threshold, or a valid enrollment — and the matrix shows
which of a principal's devices satisfy it. This is where fleet, attestation and access finally meet, and
it is the product's Zero Trust story made legible.

### 6.8 The end-user directory

Distinct from operators, and previously unrepresented. Operators run the console; **end users are the 100
people whose endpoints are protected and who reach internal services through the access proxy.** They are
the subjects of DLP decisions, UEBA baselines, entity risk and DSAR — and there was no page listing them.

Per user: identity (from the IdP, via OIDC/SCIM), their devices and each device's attestation and posture
state, their entity risk over time, their access grants (link to §6.7), open incidents, DLP decisions
affecting them, and their DSAR/erasure record. Pseudonymisation is honoured — the directory shows what the
operator's tier permits, and the privacy-officer tier is what unlocks the compiled subject view.

This is also where a leaver is verified: SCIM deprovisioned them, so **what still references them** — live
sessions, enrolled devices, pending approvals — is listed with a single "revoke everything" action.

### 6.9 Deferred surfaces — layout intent recorded now

So the shell does not have to be redesigned later: **Overview** (`CONSOLE-16`) is a tile grid where every
tile is a saved query; **Alerts** (`-17`) reuses the incident queue grid with a different row model;
**Response** (`-18`) is a three-tab surface (playbooks / runners / routing); **Evidence** (`-20`) is a
verification page plus the view-audit reader; **Configuration** (`-21`) is §8; **Admin** (`-22`) is
principals, tokens, feeds, integrations; **Policy** (`-23`) is packs-in-force plus a simulator that reuses
the Explain layout with editable inputs.

---

## 7. Workflows, with click budgets

These are the acceptance criteria for `CONSOLE-14`'s CI-gating budgets. A regression past the budget fails
the build.

| # | Workflow | Path | Budget |
|---|---|---|---|
| 1 | **Triage the top incident** | land → row → read chain + evidence | **1** |
| 2 | **Is this host compromised elsewhere?** | incident → entity pivot → related alerts | **2** |
| 3 | **Why was this blocked?** (auditor) | alert → Explain → Replay | **2** |
| 4 | **Handle a 200-incident wave** | filter → select all → bulk acknowledge → assign | **4** |
| 5 | **Tune a noisy rule** | incident → rule → suppress (scope, TTL, reason) | **4** |
| 6 | **Contain a host** | incident → Contain → step-up auth → confirm → (2nd operator approves) | **3 + approval** |
| 7 | **Shift handover** | `#team-triage` → filter mine → reassign selected | **3** |
| 8 | **Prove nothing was tampered with** | Evidence → Verify chain → export | **3** |

**Workflow 6 in detail**, because it is where the security controls surface:

1. Response column → `Contain mia@corp.example`
2. Dialog shows the **server-generated semantic summary** — *"Prevent new process execution for mia@ on
   LAPTOP-L14. Blast radius: 1 entity, 1 host. Expires in 4h unless renewed."* — above the free-text reason,
   which is quoted as untrusted.
3. **Step-up re-authentication** (`CONSOLE-25`), then confirm. The confirm button carries the one-time token
   bound to the digest of the summary shown, so a re-rendered dialog fails closed.
4. State becomes `awaiting approval`, and the requester is told plainly they cannot approve it.
5. A second operator sees it in the approval inbox with the same semantic summary and approves. If they are
   the same human under a different credential, it is refused (`CONSOLE-1`).

**No destructive action is ever a single click.** Every one of them is summary → step-up → confirm.

---

## 8. Settings and configuration IA

133 real fields — **70 server** (25 bootstrap, 45 dynamic) and **63 gateway** (all bootstrap). Presented by
`OPENSHIELD_*` name they are unnavigable. The IA groups them by *what an operator is trying to change*, and
the schema (`GET /config/schema`) supplies types, defaults, descriptions and scope.

```
Settings
├─ Detection & correlation   correlate window/interval/min-alerts/min-domains,
│                            UEBA threshold + cooldown + persist, beaconing
│                            (window/interval/min-contacts/regularity/allowlist)
├─ Incidents & response      recurrence window, escalation ladder + interval,
│                            approval expiry, blast-radius ceiling, playbooks
├─ Notifications             webhook + secret, retries, routes, dedupe retention
├─ Threat intelligence       feed path/URL/interval, feed signing key
├─ Log ingest                CEF syslog, syslog TCP/TLS, CloudTrail dir, WEF dir
├─ Retention & privacy       fleet retention, retention interval, purge, DSAR
├─ Integrations              IdP (endpoint/name/token/timeout), ITSM
│                            (interval/timeout/token), SCIM token
├─ Identity & access         operator OIDC (issuer/audience/JWKS/interval/keys),
│                            DPoP require + replay cache, clock skew, roles strict
├─ Fleet & agents            overdue threshold + interval, heartbeat, break-glass
├─ Gateway ▸ per node        egress proxy · access proxy · TPROXY · DNS sinkhole ·
│                            TLS intercept · CASB · IOC feeds · attestation · enroll
└─ Platform                  DSN, listeners, NATS, metrics, config poll, app role
```

**Rules that make this safe:**

- **Scope is visible, not hidden.** Dynamic fields are editable inline. Bootstrap fields are **read-only
  with their origin shown** (`env` / `file` / `default`) and a note that changing them requires a restart —
  because PLAT-5's whole point is that a dynamic value set in the environment is *reported, not silently
  ignored*, and the UI must show that report.
- **Secrets are write-only.** They render as `(set)` / `(unset)`, never a masked value that implies
  recoverability. Attempting to store a plaintext secret is refused by the API, and the UI says why.
- **Diff before save.** Every change set shows old → new per field, with the note field required. Save is
  one revision; **all validation errors render at once** because the API already reports them at once.
- **Revisions and rollback** are a first-class tab: who, when, what changed, and rollback-as-a-new-revision
  (never a silent undo).
- **Gateway settings are per-node**, all bootstrap, and the UI says so plainly rather than implying a
  fleet-wide apply that does not exist. This is where `TOPO-4` would eventually change the model — and
  until it lands, the honest statement is on screen.
- **Break-glass is surfaced, not hidden**, with the keys currently overridden on each host and a warning
  that an override is deliberately reported.

---

## 9. Permission matrix

What each tier *sees*, not only what it can call. A control the user cannot use is **absent or disabled
with the required tier named** — never present and silently failing.

| Surface | analyst | responder | admin | privacy-officer |
|---|---|---|---|---|
| Incidents / Hunt / Fleet / Explain read | ✓ | ✓ | ✓ | ✓ |
| Acknowledge, transition, assign, bulk | — | ✓ | ✓ | — |
| Suppression rules | propose | ✓ | ✓ | — |
| Intents (CONTAIN / REVOKE_TRUST) | — | ✓ + 4-eyes | ✓ + 4-eyes | — |
| Approve an intent | — | ✓ (not own) | ✓ (not own) | — |
| Break-glass / ENFORCEMENT_DISABLE | — | — | ✓ + 4-eyes | — |
| Configuration read / write | — | read | ✓ | — |
| Operator roles, tokens, service accounts | — | — | ✓ | — |
| DSAR export, legal-hold release, view audit | — | — | — | ✓ |
| Export from grids | ✓ (audited) | ✓ | ✓ | ✓ |

Machine principals: API only, and **never** an approval (`CONSOLE-1`).

---

## 10. Microcopy

- **Name the act, not the control.** "Prevent new process execution for mia@" beats "Contain".
- **State the blast radius as a number** in every destructive confirmation.
- **Never apologise; never blame.** "The broker is unreachable; incidents shown are current as of 09:14"
  beats "Oops! Something went wrong."
- **Say what is still true.** Degraded copy always names what the analyst *can* still rely on.
- **Attacker text is quoted, never inlined into a sentence.** The product never writes
  *"file approved-by-security.xlsx was flagged"*; it writes *"file was flagged"* with the name in an
  evidence block.
- **Uncertainty is stated in words as well as glyphs** — "inferred from pid reuse, not directly evidenced".
- **Every metric names its excluded population**, because SOAR-6 computes it and dropping it on the floor
  would overstate the number.

---

## 11. Accessibility and internationalization mechanics

- WCAG 2.2 AA: 4.5:1 body, 3:1 large and UI boundaries, in **both** themes. Verified in CI by axe plus a
  contrast unit test over the token pairs — a token file that passes review can still ship a failing pair.
- **Never colour alone**: severity carries glyph + label; evidence state carries geometry + sentence.
- Focus is always visible, 2px accent ring with a 1px inner offset so it reads on any surface. Focus is
  never removed on mouse users — a security console is used by keyboard under pressure.
- Full keyboard operation of every workflow in §7, verified as a Playwright path with the mouse disabled.
- Live regions announce new incidents at `polite`, never `assertive` — an assertive interrupt during triage
  is harmful.
- **Logical properties everywhere** (`margin-inline-start`, `padding-block`, `inset-inline`) from the first
  component, so RTL is a `dir` attribute rather than a rewrite. This stays in Phase 0 even though
  `CONSOLE-13` moved to Phase 3.
- All dates, numbers, durations via `Intl` with a selectable display timezone; **timestamps also always
  available as absolute UTC on hover**, because a handover across timezones is where incidents get
  misread.
- Plex covers the scripts; the type scale is defined in `rem` so a locale needing larger CJK line height
  adjusts via a locale-scoped variable rather than per-component overrides.

---

## 12. Responsive and density

Not a mobile product. Three breakpoints:

- **≥1600px** — three-column incident detail, full grid.
- **1200–1600px** — response column collapses to a tab beside evidence.
- **<1200px** — single column, chain becomes a collapsible header. Below 900px the console shows a
  supported-resolution notice rather than degrading into an unusable grid; pretending is worse.

Density toggle (compact / default / comfortable) persists per operator, and **comfortable is the
accessibility default** when the OS requests larger text.

---

## 13. Capability coverage — every product domain, and which surface serves it

The first draft of this plan designed the **investigation** half well and the **administration, policy and
tuning** half barely at all. That is a predictable bias — investigation is what a demo shows — and it is
what the tuning and Zero Trust gaps above both came from. This matrix exists so the remaining gaps are
visible rather than discovered by a customer.

Legend: ✅ specified · 🟡 partial · ❌ no surface.

| Domain | Operate / investigate | Configure / author | Tune |
|---|---|---|---|
| **XDR** correlation, entities, timeline | ✅ §6.2, §6.4 | 🟡 correlation params in Settings | ✅ §6.6 |
| **SOAR** playbooks, intents, approvals, routing | ✅ §6.2 response column, approvals | 🟡 `CONSOLE-18/-19`, read + dry-run only | ✅ §6.6 |
| **Zero Trust** catalog, policy, sessions, posture | ✅ §6.7 | ✅ §6.7 ③ | n/a |
| **SIEM** search, external ingest, saved views | ✅ §6.3 | 🟡 ingest endpoints in Settings | ✅ §6.6 |
| **DLP** detection, EDM/IDM, packs, channels | 🟡 alerts + Explain | ❌ **`CONSOLE-49`** — no index/classifier surface | ✅ §6.6 |
| **NIPS/NTPS** IOC, signatures, sinkhole, CASB | 🟡 alerts + Explain | ❌ **`CONSOLE-48`** — no rule/feed/list surface | ✅ §6.6 |
| **HIPS** exec control, FIM, canary, USB | 🟡 alerts + Fleet | ❌ **`CONSOLE-47`** — no allow/deny or baseline surface | ✅ §6.6 |
| **Device trust** enrollment, attestation, PCR | 🟡 Fleet columns | ❌ **`CONSOLE-50`** — no enrollment or PCR-policy surface | n/a |
| **Identity** operators, service accounts, tiers | 🟡 `CONSOLE-22` | 🟡 `CONSOLE-22` | n/a |
| **End users** directory, access, subjects | ✅ §6.8 | ✅ §6.8 | n/a |
| **Evidence** ledger, anchors, view audit | 🟡 §6.2 panel; `CONSOLE-20` full | n/a | n/a |
| **Privacy** DSAR, legal hold, retention | ❌ **`CONSOLE-51`** — only a `/subject` link exists | 🟡 retention in Settings | n/a |
| **Platform** config, health, break-glass, releases | ✅ §6.4, `CONSOLE-7` | ✅ §8 | n/a |

**The pattern in the ❌ column is one sentence:** every domain that *detects* has a shipped, tested
detection plane and **no way to see or change what it is detecting on** without editing a file on a host.
Four surfaces close it — endpoint control (`-47`), network defense (`-48`), DLP classifiers (`-49`), device
trust (`-50`) — plus privacy operations (`-51`). None of them gate the MVP console. All of them gate the
sentence *"an administrator can run this product from the console"*, which is a different and later claim,
and the roadmap should not let the two be confused.

**They also share a shape worth designing once:** each is a list of rules, feeds, baselines or lists, each
entry needing origin (file / URL / operator-authored), signature state where the artifact is signed, last
reload, hot-reload vs restart, a dry-run, and a diff-and-approve on change. That is one component family
reused five times, not five bespoke pages — and specifying it once is `CONSOLE-46`.

## 14. What this spec does not cover

Named so nobody assumes it: no visual design for the deferred surfaces beyond layout intent (§6.9); no
topology canvas interaction model — that is `TOPO-2`, specified separately in
`2026-07-31-topology-canvas-spec.md`; no email/notification
template design; no marketing or docs site; no mobile or tablet layouts; no white-label theming beyond the
CSS-custom-property seam; and no motion spec for the timeline beyond the single first-load draw-in.
