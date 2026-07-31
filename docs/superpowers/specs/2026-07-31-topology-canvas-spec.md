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

Twelve kinds, from `TOPO-1`. Each node renders as a **72×72 rounded square with a 20px kind glyph, a name,
and a state rail across its bottom edge** — deliberately not a card, because the console reserves cards for
the one moment that means "stop and read this" (approval).

| Kind | Glyph | Ports (in / out) |
|---|---|---|
| External network / Internet | ◍ | — / any |
| Gateway · egress proxy | ⧉ | any / service, external |
| Gateway · ZT access proxy | ⛨ | user, agent-group / service |
| Gateway · inline TPROXY | ⇥ | any / any |
| Gateway · DNS sinkhole | ⌁ | any / external |
| Control-plane server | ▣ | agent-group, gateway / broker, database |
| Worker | ⚙ | server / — |
| Endpoint agent **group** | ▤ | — / gateway, server |
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

## 3. Scale — the problem every topology canvas fails

A hundred endpoints cannot be a hundred nodes. Neither can a thousand. Three mechanisms, applied in order:

**① Endpoints are never individual nodes.** They aggregate into **agent-group** nodes by site, platform,
enrollment tag or OU. Expanding a group opens a **list panel beside the canvas**, not a hundred nodes on
it. This is non-negotiable and is a model decision, not a rendering one: `TOPO-1` stores the grouping
predicate, so the group is stable across sessions and shared between operators.

**② Semantic zoom, three tiers.** Zoom changes *what is drawn*, not merely its size:

| Zoom | Shows | Node count target |
|---|---|---|
| **Sites** (< 40%) | site containers, inter-site links, aggregate health | ≤ 12 |
| **Zones** (40–90%) | gateways, services, agent groups, brokers | ≤ 60 |
| **Detail** (> 90%) | + individual ports, edge labels, per-node counters | ≤ 60 in viewport |

**③ A hard budget with an honest failure.** Above **150 nodes at the current tier** the canvas stops
auto-laying-out and shows: *"This view has 214 nodes. Group by site to continue, or filter."* — with the
grouping controls right there. It does **not** silently render an unusable hairball and let the operator
conclude the feature is broken. A canvas that degrades without saying so is worse than one that refuses.

**Layout.** Deterministic layered layout (rank by edge direction: external → gateway → service → data),
because a force-directed graph that settles differently on every load destroys spatial memory — and spatial
memory is the entire reason a map beats a list. Operator-moved nodes pin and persist in the revision;
`Auto-arrange` is explicit and undoable, never automatic on load.

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

## 9. What this spec does not cover

No auto-discovery of *undeployed* infrastructure (the model knows only what enrolled or was declared — it
does not scan networks, and it must never imply it does). No cost or capacity modelling. No simulation of
traffic volume. No topology-driven alerting. No canvas on mobile — the tree view is the small-screen answer,
and it is not a degraded one. And no `TOPO-4` apply flow, which needs its own spec once the signed channel's
shape is decided by the owner.
