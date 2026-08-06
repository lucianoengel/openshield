# Design — CONSOLE-9

## The page is a count of entities, not of rows

`Entities` selects the newest N entities and *then* joins their aliases, rather than limiting the joined
result. A limit applied to the flat join would return a partial entity — and half a coalesced identity is
worse than none, because it looks complete. An operator would see a device with one alias and conclude it
had never been linked to a user.

## Risk is absent, not zero

`EntityRisk` is driven from `unified_alerts` over a window, so an entity with no alerts in that window
produces no row. Reporting that as `0.0` would say "we assessed this asset and it is fine"; the truth is
"nothing has been seen recently". Those are different answers to the question an operator brings to this
page, so `Risk` is a pointer and absent means absent.

Same rule the fleet roster applies to never-seen agents and never-reported enforcement (D473/D474). It is
becoming the house pattern: a zero value that a reader could mistake for a measurement must be nullable.

## A read must not create

`Resolve` creates the entity on first sight — correct for ingest, wrong for a lookup. `EntityFor` returns
`found=false` instead, because a read that invented an entity would make the graph grow by being looked
at, and every typo in a console search would leave a permanent empty node.

For the same reason the route answers **404** rather than an empty object when nothing matches: "no
entity is known by that name" and "this entity has nothing recorded" are different answers, and a console
rendering both as an empty page would let a typo look like a clean asset.

## An entity with no aliases is reported, not dropped

`Resolve` creates entity and alias in one transaction, but a merge can leave a node behind. The reader
reports it with an empty alias list. A node nothing names is exactly the kind of thing an operator should
be able to see, and silently skipping it would hide the one case worth investigating.

## Tier: analyst

Argued in the proposal. The short form: the graph holds pseudonyms, not identities; re-identification is
`/subject` and belongs to the privacy officer; and the tier that triages alerts is the tier that needs the
pivot.
