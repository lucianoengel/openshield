# Topology canvas — interaction specification (TOPO-2)

**Date:** 2026-07-31 · **Lane G** · **Companion to:** `2026-07-31-console-ux-spec.md` (design system,
states, chrome) and `2026-07-31-console-plat1-design.md` §8 (model, compiler, ADR-15)

---

## 1. What this is, and the one sentence that governs it

> **The canvas is a view of a reconciled model, not a drawing of a network.**

Everything in this spec follows from that. The graph has two populations — what an operator **declared**
and what the fleet **actually reports** — and the canvas's job is to show both at once and make their
disagreement legible. A tool that only draws intent is a diagram that goes stale in a week. A tool that only
draws discovery is a map with no opinion about whether reality is correct.

**It is not n8n, and the difference matters.** In n8n the graph *is* the program: nodes exist because you
drew them, and running it executes what is on screen. Here, **nodes exist whether or not you draw them**. A
gateway that enrolled this morning appears on the canvas uninvited. The n8n-ness worth keeping is the
*editing affordance* — direct manipulation, ports, drag-to-connect, a configuration panel beside the
selection. The n8n-ness that would be actively dangerous is the assumption that the canvas is the truth.

Three rules make that concrete, and they are the ones to keep if everything else is cut:

1. **You cannot delete reality from the canvas.** Deleting a discovered node removes your *declaration*
   that it should exist. The node stays, now marked `undeclared`. The confirm copy says exactly that.
2. **An edge is an assertion of intent, never an act.** Drawing `gateway → prod-web` declares *"this traffic
   should pass through this gateway."* Whether it does is drift, and drawing it changes nothing until
   compile and apply.
3. **The canvas never applies anything.** Phase 2 compiles to a proposed config; Phase 3 applies over the
   signed channel with four-eyes (`TOPO-4`/`-5`, owner-gated). Until then the primary action on the canvas
   is *Save declaration*, and it is honest about producing no change in behaviour.

---

## 2. The node model on screen

### 2.0 A node is a ROLE, not a machine

**This is the decision that makes the whole feature tractable.** A node represents a *class of traffic or
function* — "user endpoints", "internet", "internal services", "the gateway in front of production" — with
a **population** behind it. It is not an inventory item.

So there is one `user endpoints` node standing for all 51 laptops, one `internet` node standing for all
external traffic, one `internal services` node per zone. The population is an attribute of the node
(a count, a health distribution, a member list in the side panel), never a set of nodes on the canvas.

Three consequences, all simplifications:

- **The canvas stays small by construction.** A real deployment is 8–20 nodes, not 200. The elaborate
  scale machinery an inventory graph would need — semantic zoom tiers, grouping predicates, node budgets —
  is not needed and is not built. §3 is what survives of it.
- **The diagram matches how operators already think and draw.** People whiteboard *"internet → gateway →
  prod"*, not fifty-one laptops. The canvas should look like the whiteboard, because that is the mental
  model it has to confirm or contradict.
- **A node is stable.** Endpoints enrol and leave constantly; the *role* "user endpoints" does not. So the
  declared model stops churning, and drift becomes meaningful — a changing graph cannot show drift, because
  everything is always changing.

Membership is a **predicate**, stored in the model (`TOPO-1`): platform, enrolment tag, OU, subnet, site.
An endpoint that matches no node's predicate is itself a drift finding — *"7 enrolled agents belong to no
declared node"* — which is exactly the population an inventory diagram would have hidden in plain sight.

### 2.1 Kinds and ports

Twelve kinds, from `TOPO-1`. Each node renders as a **72×72 rounded square with a 20px kind glyph, a name,
a population count, and a state rail across its bottom edge** — deliberately not a card, because the console
reserves cards for the one moment that means "stop and read this" (approval).

| Kind | Glyph | Ports (in / out) |
|---|---|---|
| External network / Internet | ◍ | — / any |
| Gateway · egress proxy | ⧉ | any / service, external |
| Gateway · ZT access proxy | ⛨ | user, agent-group / service |
| Gateway · inline TPROXY | ⇥ | any / any |
| Gateway · DNS sinkhole | ⌁ | any / external |
| Control-plane server | ▣ | agent-group, gateway / broker, database |
| Worker | ⚙ | server / — |
| **User endpoints** (a role, any population) | ▤ | — / gateway, server |
| Internal service | ▢ | gateway / database |
| Identity provider | ⊙ | — / gateway, server |
| Broker (NATS) | ⇄ | server, gateway, agent-group / — |
| Database | ⛁ | server, service / — |
| Site / zone container | ⬚ | (container — nests others) |

**Ports are typed and the type is enforced at drag time.** Dragging from an agent-group's out-port shows
only gateways and servers as valid drops; everything else dims to 30%. An edge that cannot typecheck cannot
be drawn — the model rejects it (`TOPO-1`), so the canvas must not let a user express it and then explain
the rejection afterwards.

### 2.1 Binding: discovered vs declared

Every node carries one of three bindings, and this is **the primary information on the canvas**, so it gets
the strongest non-colour encoding available — the border, matching how the console encodes evidence state:

```
┌────────┐     solid border      DECLARED + DISCOVERED
│   ⧉    │     filled glyph      you declared it and the fleet reports it. The good state.
└────────┘

┌╌╌╌╌╌╌╌╌┐     dashed border     DECLARED, NOT DISCOVERED
╎   ⧉    ╎     hollow glyph      you say it should exist; nothing has enrolled.
└╌╌╌╌╌╌╌╌┘                       Either not deployed yet, or it died.

┏━━━━━━━━┓     double border     DISCOVERED, NOT DECLARED
┃   ⧉    ┃     filled glyph      it is out there and your model does not mention it.
┗━━━━━━━━┛     + corner mark     The one that should worry you.
```

**Colour is not used for binding**, because the console's law is that saturated colour means severity and
nothing else. Binding is border geometry; health is the state rail; severity, where a node has active
incidents, is the only coloured element on the node — a single severity chip in the top-right corner, which
is therefore the only thing that draws the eye across a large canvas. That is the intent.

`DISCOVERED, NOT DECLARED` is the state the product exists to surface — an enforcement point nobody
documented, or worse, an enrolled agent on a host nobody knew about. It gets a persistent count in the
canvas toolbar: **`⚠ 3 undeclared`**, always visible, one click to select them all.

### 2.2 The state rail

A 4px rail across the node's bottom edge, segmented, using the neutral ramp plus hatching — never colour:

```
▤ agent-group "eng-laptops"     ████████░░░░  42 of 51 healthy
                                ▨▨            5 attestation stale (hatched)
                                    ▬▬        4 enforcement suppressed (struck)
```

For a single node it is binary (reporting / silent). For an **agent group** it is proportional, and this is
what makes a group node worth more than a count: 51 endpoints as one node with a rail that shows nine of
them are not in a good state, expandable to the list.

---

## 3. Scale — mostly solved by §2.0

Because nodes are roles, a real deployment is **8–20 nodes**. The canvas is not an inventory graph and does
not need the machinery one would require. What remains:

- **Site containers** nest nodes for multi-site deployments, collapsible to a single node with aggregate
  health. That is the only hierarchy.
- **Population never becomes geometry.** Expanding `user endpoints` opens a **list panel beside the
  canvas** — sortable, filterable, exportable — never fifty-one nodes.
- **A soft ceiling with an honest failure.** Past ~60 nodes the canvas warns that the model has probably
  drifted from roles toward inventory, and points at the site containers. It does not silently render a
  hairball and let the operator conclude the feature is broken.

**Layout.** Deterministic layered layout (rank by edge direction: external → gateway → service → data),
because a force-directed graph that settles differently on every load destroys spatial memory — and spatial
memory is the entire reason a map beats a list. Operator-moved nodes pin and persist in the revision;
`Auto-arrange` is explicit and undoable, never automatic on load.

## 3a. The node is the configuration surface

A second reason roles beat instances: **a role is exactly the right scope for a setting.**

The console has **133 configuration fields** (70 server, 63 gateway) and the Settings IA groups them by
subject matter, which is correct but still asks the operator to already know where a thing lives. The
topology gives the same fields a *spatial* index: click the gateway in front of production and configure
that gateway; click `user endpoints` and configure the endpoint agent policy that population receives.

Rules that keep this from becoming a second, drifting configuration model:

- **The panel renders the same schema-driven forms as Settings** (`GET /config/schema`), not a bespoke
  editor. One renderer, two entry points. A field added in Go appears in both without anyone updating a
  diagram.
- **Scope is stated on the node**, because it differs sharply and silently: gateway settings are
  bootstrap-scope and node-local (D272, restart required), while most server settings are dynamic and
  cluster-wide. The panel says which it is *before* an edit, not after a save that appeared to do nothing.
- **A role-scoped setting is only offered where one genuinely exists.** Where a setting is per-host and the
  node stands for many hosts, the panel shows the *distribution* of current values across the population and
  refuses to pretend a single field sets them all. This is the honest failure mode, and it is the one that
  would otherwise ship a lie.

Navigating configuration by picture is a real usability win over a 133-row list, and it costs nothing new —
it is a second route into machinery that already exists.

---

## 4. Drift — the feature, not a badge

Drift is why this is an operations surface rather than Visio. It is computed server-side (`TOPO-1`) and
rendered in three places so it cannot be missed:

**On the node** — border geometry (§2.1).

**On the edge** — three states, matching the incident timeline's vocabulary so an operator learns one
language:

```
━━━━━━━▶   declared and observed      traffic is flowing this way and you said it should
╌╌╌╌╌╌▶    declared, not observed     you said it should; no traffic or rules confirm it
━━?━━━▶    observed, not declared     it is happening and your model does not say so
```

**In the drift panel** — a list, sorted by risk, that is *also reachable from the Fleet page without ever
opening the canvas* (`TOPO-1` ships this before `TOPO-2` draws anything):

```
DRIFT · 7 findings                                        [ Accept selected into model ]
──────────────────────────────────────────────────────────────────────────────────────
⚠ HIGH   gateway gw-edge-02 is enforcing TPROXY rules on :443 that the model
         does not declare                                    [ Inspect ] [ Declare ]
⚠ HIGH   service prod-db is reachable from zone "contractors" per policy,
         but no gateway is declared in that path             [ Inspect ] [ Declare ]
  MED    agent-group "eng-laptops": 5 of 51 report to gw-edge-01,
         model declares gw-edge-02                           [ Inspect ] [ Declare ]
  LOW    declared node "gw-branch-03" has never enrolled (declared 34d ago)
                                                             [ Inspect ] [ Remove ]
```

**`Declare` reconciles the model to reality — it never changes reality.** The button text is `Declare`
rather than `Fix` precisely because "fix" implies the fleet moves. This is the single most likely
misunderstanding of the whole feature and it is defended in the copy, the confirm dialog, and the
post-action toast (*"Model updated. No configuration was changed."*).

---

## 4a. Edge health — "is the network operating as described?"

Drift (§4) answers *does the configuration match the declaration.* This answers a different and more
operationally useful question: **is traffic actually flowing the way the model says it should, right now?**
It is what turns the canvas from a reconciliation tool into a monitoring surface, and it is the strongest
argument for the feature existing at all.

Two tiers, and the ordering is a safety decision.

### Tier 1 — passive, derived from telemetry already flowing (default, always on)

Every declared edge is scored from evidence the platform already collects, with **no new traffic
generated**:

| Edge | Existing signal |
|---|---|
| endpoints → gateway | agent heartbeats, decisions attributed to that gateway |
| gateway → internal service | proxy/access-proxy decisions naming that upstream |
| endpoints → control plane | heartbeat freshness, spool depth, enrolment state |
| gateway/server → broker | JetStream consumer health, publish counters |
| user → ZT service | access-proxy allow/deny counts per catalogued service |

Each edge shows **last observed traffic**, a rate sparkline, and one of four states:

```
━━━━━━━▶  healthy      observed within the expected interval
━━━━━━━▶  quiet        no traffic, and none expected (low-volume path)  — neutral, not a fault
╌╌╌╌╌╌▶   silent       declared, expected, and NOT observed for 22m     ⚠
━━✕━━━▶   failing      observed and being REFUSED (auth, policy, upstream error)
```

**`silent` and `failing` are different failures and must never be merged.** Silent means the path is not
being used — a routing change, a dead upstream, an agent that stopped. Failing means the path *is* being
used and is being rejected — which is often correct behaviour (default-deny working) and occasionally an
outage. A single red line conflating them sends operators to the wrong place, so the state carries the
distinction and the panel explains it.

**"Expected" must be declared, not inferred.** An edge carries an expected-traffic interval set by the
operator (or "none"), because inferring expectation from history means a path that broke last week is
silently reclassified as normal. That is the trap this design refuses.

### Tier 2 — active reachability probes (opt-in, off by default)

Passive cannot distinguish *"nobody tried"* from *"it is broken"* on a quiet path. Synthetic probes can —
and they are **off by default, per-edge opt-in, and audited**, for a reason worth stating plainly:

> **A security product that probes internal services is generating exactly the traffic it is built to
> detect.** Unscoped, it trips the customer's other controls, pollutes its own telemetry, and looks like
> reconnaissance in someone else's SIEM.

So probes: run from a declared node toward a declared node only (never arbitrary addresses — the same
allow-list discipline the access catalog uses to avoid being an SSRF pivot); are rate-limited and carry a
stable identifying marker so they are recognisable in any log; are attributed to the operator who enabled
them; and **are excluded from detection and from UEBA baselines**, or the product raises alerts on itself
and skews the baselines it uses to find real anomalies.

Probe results feed the same four states. The canvas always shows **which tier produced the state**, because
"we saw real traffic" and "our own probe succeeded" are different evidence and a monitoring surface that
blurs them is not trustworthy.

### What this is not

Not a network monitor and it must not imply it is. It knows about **declared edges between declared
nodes** — nothing about links it was never told about, nothing about latency budgets or capacity, and
nothing about hosts that never enrolled. `TOPO-6` ships Tier 1; Tier 2 is a separate ticket with its own
opt-in.

## 5. Editing

**Read-only by default, for everyone.** Edit mode is an explicit toggle, requires the admin tier, and is
visible in the chrome (the canvas border becomes accented and the toolbar changes) so nobody edits by
accident while investigating.

- **Add** — palette rail on the left, drag onto canvas, or `⌘K → "add gateway"`. A new node is `DECLARED,
  NOT DISCOVERED` by definition, and the panel says so.
- **Connect** — drag port to port; invalid targets dim; releasing on empty canvas offers the valid node
  kinds for that port rather than cancelling.
- **Configure** — right panel, driven by the same schema machinery as Settings (§8 of the UX spec), so
  gateway node configuration is the *same forms* as `/config/schema` renders and cannot drift from it.
- **Delete** — see rule 1. Discovered nodes cannot be deleted, only undeclared.
- **Undo/redo** — full stack, `⌘Z`/`⇧⌘Z`, within the editing session.
- **Saving is explicit and revisioned.** No autosave. `Save declaration` opens a diff — nodes added,
  removed, edges changed, config fields altered — with a required note, exactly like a config revision
  (author, diff, rollback). Leaving with unsaved changes prompts.

### 5.1 Coverage, shown while editing — not at approval

This is the most important interaction in the spec, and it comes straight from ADR-15.

A compiled topology change that **reduces enforcement coverage** must be refused unless expressed as
`ENFORCEMENT_DISABLE`, so that it inherits four-eyes, monotonic sequencing and a mandatory TTL rather than
routing around them. The UX consequence: **coverage loss must be visible at the moment of the edit**, not
discovered at approval, because an operator who learns at approval time has already built a change set
around a false assumption.

So the canvas carries a live **coverage meter** in the toolbar, recomputed on every edit:

```
COVERAGE   inline inspection 12/14 services   ·   DNS sinkhole 3/3 zones   ·   ZT-fronted 8/8
```

and the moment an edit reduces it:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ⚠  This edit removes inline inspection from prod-web and prod-api.       │
│                                                                          │
│    Deleting this edge takes gw-edge-01 out of the path for 2 services.   │
│    A change that reduces enforcement coverage cannot be applied as a     │
│    routing change — it must be requested as ENFORCEMENT_DISABLE, which   │
│    requires two-person approval and carries a mandatory expiry.          │
│                                                                          │
│    [ Undo this edit ]     [ Continue and request ENFORCEMENT_DISABLE ]   │
└──────────────────────────────────────────────────────────────────────────┘
```

The operator can still do it. They cannot do it *quietly*, and they cannot do it while believing they are
only moving a line.

---

## 6. Compile — the diff that is the real deliverable (`TOPO-3`)

`Compile` runs the pure function and produces, per affected node, the configuration it would receive —
never applying. Three panes:

**① Semantic summary**, first and largest, because ADR-15 requires approval to be semantic:

> *prod-web loses inline inspection. Traffic from zone `contractors` to `prod-db` gains a ZT access
> requirement (attested device). gw-edge-02 begins sinkholing DNS for zone `branch`.*

**② Per-node field diff**, collapsed by default:

```
gw-edge-01                                       ▾
  OPENSHIELD_TPROXY_DPORTS      80,443  →  80
  OPENSHIELD_ACCESS_CATALOG     (unchanged)
  ⓘ all gateway settings are bootstrap-scope — this node requires a restart
```

**③ What cannot be applied yet.** Until `TOPO-4` ships there is no signed channel, and gateway settings are
node-local by design (D272). So the compile output ends with an honest terminal state rather than a
disabled `Apply` button implying it is nearly ready:

> **This configuration cannot be delivered from the console.** Gateway settings are node-local and there is
> no signed fleet-wide configuration channel yet (`TOPO-4`). Export the per-node configuration, or apply it
> through your existing configuration management.
> `[ Export per-node config ]  [ Copy as env ]  [ Download bundle ]`

**Export is the product until `TOPO-4`.** That is not a consolation prize — a validated, typechecked,
coverage-checked configuration generated from a reconciled model is genuinely useful with Ansible or a
Containerfile, and shipping `TOPO-3` as export-only means Lane G delivers value two owner-gated tickets
earlier than it otherwise would.

---

## 7. Accessibility — the tree is not a fallback, it is the model

A node canvas is the hardest accessibility problem in any console, and the usual outcome is a keyboard trap
with an apology. The rule here:

> **The canvas and the tree are two views of one model. Both are fully editable. Neither is secondary.**

The tree view is a nested, `aria-tree` structure — sites → zones → nodes → edges — with every operation from
§5 available: add, connect (via a "connect to…" combobox rather than a drag), configure, undeclare, save. It
is the screen-reader path, the keyboard path, and *also* genuinely the faster path for bulk edits, which is
what stops it rotting: sighted keyboard users choose it, so it stays maintained.

- Canvas nodes are focusable in layout order; arrow keys move between connected nodes (`→` follows an
  outbound edge, `←` inbound), `Tab` moves to the next unconnected component.
- Every node announces kind, name, binding state, health summary and edge count.
- Selection, drift state and coverage warnings are announced in a `polite` live region.
- The canvas honours `prefers-reduced-motion`: no pan easing, no layout animation, edges redraw instantly.
- Zoom never falls below the type-legibility floor; below it, labels drop to the tier's aggregate names
  rather than shrinking into illegibility.
- **Nothing is conveyed by colour alone anywhere in this spec** — binding is border, drift is stroke
  pattern, health is rail segmentation, severity carries its glyph.

---

## 8. States

The nine from the UX spec §4, with canvas-specific readings:

| State | Canvas |
|---|---|
| Loading | Skeleton node placeholders in the final layout positions; no shimmer. |
| Empty · unconfigured | Not a blank canvas. Shows *discovered* nodes with the message "Nothing is declared yet. 6 nodes were discovered — start by accepting them into the model." One click to declare all. |
| Empty · no discovery | "No agents or gateways have enrolled" + the enroll command, matching `CONSOLE-33`. |
| Filtered to nothing | Filter chips shown with one-click clear; the node count reads `0 of 214`. |
| Error | The model failed to load: the canvas does not render a partial graph, because a partial topology reads as a complete one. |
| **Degraded** | Discovery is stale — the canvas dims discovered state, keeps declared state crisp, and banners *"drift last computed 14m ago; nodes may have changed."* **A drift finding is never shown as current when its input is stale**, because acting on stale drift means declaring something that is no longer true. |
| Stale | Amber timestamp on the coverage meter and the drift panel. |
| Forbidden | Analysts see the canvas read-only with the edit toggle absent and the required tier named. |
| Conflict | Another operator saved a revision while you were editing: a diff of theirs vs yours, and a merge or rebase choice. No last-write-wins. |

---

## 8a. AI topology review — where it would fit, and the guardrails it needs

Recorded because the owner named it as a future direction, and because the topology is one of the few
places an assistant could add real value with **bounded** risk. It remains part of the 🔒 owner-gated AI
lane (ADR-16) and gates nothing in Lane G.

Why the fit is unusually good: the topology is **small, structured, declared by a human, and not
attacker-controlled**. That last property is what makes it different from every other AI use in this
product — an assistant reasoning over incident evidence is reasoning over data an attacker wrote, whereas an
assistant reasoning over the topology is reasoning over operator-authored declarations plus the platform's
own health signals. The prompt-injection surface is close to nil.

What it could usefully say:

- *"`prod-api` is declared behind no gateway — every other service in this zone is behind `gw-edge-01`."*
- *"Zone `contractors` reaches `prod-db` directly; every comparable deployment fronts it with ZT access."*
- *"This edge has been `silent` for 11 days and was healthy before that."*
- *"You have 7 enrolled agents matching no declared node."*

The guardrails, all of which fall out of the rules already in this spec:

- **It proposes declarations, never applies configuration.** Its output is a diff on the model that a human
  saves — it enters at exactly the point a human edit enters, and inherits §5.1's coverage check and §6's
  compile and approval path unchanged.
- **It cannot suggest a coverage reduction without that being surfaced as one.** The coverage meter runs on
  its proposals identically; there is no path where an AI-authored edit skips the `ENFORCEMENT_DISABLE`
  gate.
- **Every suggestion cites the observation it came from** — a drift finding, an edge state, a population
  count — and an uncited suggestion is not rendered, matching the AI lane's citation rule.
- **It is never the source of a health verdict.** It may summarise `silent`/`failing` states; it may not
  produce them, because those are measurements and measurements must stay reproducible.

## 9. What this spec does not cover

No auto-discovery of *undeployed* infrastructure — the model knows only what enrolled or was declared, it
does not scan networks, and it must never imply it does. No cost or capacity modelling, no latency budgets,
no simulation of traffic volume. **No topology-driven alerting**: edge states are visible on the canvas and
in the drift panel, and routing them into the alert pipeline is a separate decision, because a monitoring
signal promoted to an alert without tuning is how the queue fills with noise (see `CONSOLE-41`). No canvas
on mobile — the tree view is the small-screen answer and is not a degraded one. No `TOPO-4` apply flow,
which needs its own spec once the signed channel's shape is an owner decision. And **no active probing in
`TOPO-6`** — Tier 1 is passive only; Tier 2 is separately ticketed and off by default.
