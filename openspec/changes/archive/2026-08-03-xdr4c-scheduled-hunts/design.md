# Design — XDR-4c scheduled hunts

## Why a file and not more env vars

A hunt is a name plus two ordered lists plus three thresholds. Expressing N of those as flat env vars
means either `OPENSHIELD_HUNT_1_SEQUENCE`-style numbering or a single densely-encoded string, and both
make the operator's most important artefact — the narrative they are hunting for — the least readable
thing in the configuration.

`OPENSHIELD_ESCALATION_LADDER` established the pattern for exactly this shape: a `KindPath` to JSON,
re-read per tick, validated at load, and a parse failure that leaves the feature OFF and says so rather
than substituting a default. The reasoning recorded there transfers verbatim — *"guessing at deadlines
an operator did not write would page people on a schedule nobody agreed to"* — and here the guess would
be raising incidents against a narrative nobody wrote.

Per-tick re-read is not a nicety. A loop holding the hunts it was constructed with makes "dynamic"
mean "dynamic once you restart", which is the shape PLAT-5b exists to refuse.

## Validation at load, against the real vocabularies

The HTTP handler already refuses an unknown domain and an underivable technique, with the offending
value quoted, because a step nothing can emit would never match and the operator would read the empty
result as "that attack chain did not happen". A hunt file is the *same* input arriving through a
different door, and the failure is worse there: an interactive query at least returns immediately, while
a mis-typed hunt sits in the file silently matching nothing for as long as it is deployed.

So `LoadHunts` applies the same two checks, plus:

- **A hunt must be named**, and names must be unique. The name is the incident's identity (below), so an
  empty or duplicate name would silently merge two hunts into one incident.
- **A hunt must constrain something.** A hunt with neither sequence is just the breadth rule under
  another name; it would raise a second, identical incident for every entity the breadth rule already
  caught, and an operator would reasonably read two incidents as two findings.

Every rejection names the hunt and the offending value. "hunts failed to load" is not actionable.

## The collision, and why the index reshape is mandatory

Migration 028 wrote the argument when it added the cross-domain rule alongside the burst rule:

> Left as-is, a burst incident and a cross-domain incident for the same asset would collide and the
> second upsert would silently overwrite the first — an operator would lose an incident with no trace.

Two hunts are that situation one level down. They share `kind = 'cross_domain'`, so both conflict
targets — `incidents_open_entity_idx (entity_id) WHERE state='open' AND kind='cross_domain'` and
`incidents_open_kind_subject_idx (kind, subject_id) WHERE state='open'` — treat them as the same
incident.

What that produces is worse than a lost row, because it looks like it is working:

1. Hunt A matches entity 5, INSERTs, pages. Correct.
2. Hunt B matches entity 5 on the same tick, takes `DO UPDATE`, overwrites `alert_count`,
   `domain_count` and `domains` with its own narrower numbers.
3. `RETURNING (xmax = 0)` is false, so **hunt B never pages.** A second, different attack narrative on
   the same asset is silently folded into the first one's incident.
4. Every subsequent tick the row flip-flops between whichever hunts still match.

So `rule_name` joins both indexes. `''` is the breadth rule — which is exactly what every existing row
is, so the migration needs no backfill and invents nothing.

## Why the breadth rule keeps running

A sequence rule is strictly *narrower* than the breadth rule it derives from: it adds constraints and
never relaxes one. Replacing the breadth rule with hunts would therefore lose detections — the whole
class of "three domains lit up on one asset in a shape nobody wrote a hunt for", which is the case the
breadth rule exists to catch and the one a hunt by definition cannot anticipate.

They are additive. Configuring hunts adds incidents; it never removes one.

## The page names the hunt

`notifyCrossDomainIncident` currently reports severity, alert count, domain count and the domain list.
For a breadth incident that is the whole finding. For a hunt it is not even the interesting part: the
finding is *which narrative matched*, and two hunts on the same asset produce identical text without
the name.

The name is operator-authored free text, so it is treated the way `Decision.reason` is treated in
`alertTitleFor` — it goes into the notification a human reads, and **not** into any derived table's
title or dedup key beyond the `rule_name` column it identifies the rule by. A hunt named after a
customer's file path would then be a content leak in a widely-read index.

## Contradiction check

None. `cross-domain-correlation`'s archived requirements say materialization is idempotent, raises at
most one incident per entity, and pages once. All three survive: idempotent per (entity, rule), one
incident per (entity, rule), and one page per genuine insert. The "at most one incident per entity"
requirement is *modified* rather than contradicted — it becomes per entity per rule, which is what it
already meant when only one rule existed.
