## Context

Two requirements restored by D322 contradict the product. Settling them required establishing what the
product actually prevents, which turned out to be a per-domain answer rather than a yes or no.

| domain | inline prevention today | mechanism |
|---|---|---|
| execution | **yes** | `FAN_OPEN_EXEC_PERM` answered `FAN_DENY` (HIPS-3, `openshield-agent`) |
| network flow | **yes** | NIPS-1 TPROXY drop at L4; gateway refuses before forwarding |
| print job | **yes** | CUPS filter refuses before the job reaches the printer |
| clipboard paste | **yes**, where the display server allows mediation | X11 selection ownership |
| USB device | **yes** | sysfs deauthorization |
| **file open** | **no** | nothing answers `FAN_OPEN_PERM` |

## Decisions

### The old enforcement requirement was right, and is still right about files

The temptation was to treat it as obsolete. It is not. Its reasoning — *"the file was already read, that
is how it was classified"* — is a statement about an unavoidable ordering, not about an unfinished
feature, and it still holds. You cannot block an open on a content classification that requires the open.

What changed is that other channels arrived where the decision does NOT require reading the content:
an exec is decided on a path or hash, a flow is decided on its destination, a device on its identity. The
requirement generalized from the one channel that existed to all channels, and the generalization is what
expired.

So the replacement is per-domain, and each claim names its mechanism. That is a stronger anti-overclaim
rule than the original, not a weaker one: "we do not prevent" is unfalsifiable and ages badly, while
"an exec is prevented by answering the permission event with DENY" can be checked and can be wrong.

### The file-open prefilter is designed and unwired, which is why the file row still says no

`internal/agent/prefilter` implements the two-tier answer to this exact problem — a cheap synchronous
verdict inside the permission window, with full classification asynchronously — and `grep` finds no
caller outside its own package. The `inline-prevention` capability already carries a requirement for it
("A two-tier prefilter answers the permission window"), so this is the unwired shape catalogued in
`docs/unwired-audit.md`: a design with tests and no runner.

Recorded rather than fixed. Wiring it needs a privileged agent mode that marks `FAN_OPEN_PERM`, a
partial-classification path through the sandboxed worker, and a root-gated kernel test — a change of its
own. The honest consequence is that the requirement stays in the spec as design, and the enforcement
requirement states plainly that file access is not prevented today.

### REMOVED, not MODIFIED, because the NAME is the claim

Both old requirements are named after the thing that is no longer true — "Post-decision enforcement
contains, it does not prevent", "Phase 1 records decisions without acting on them". Editing the body
under an unchanged heading would leave the wrong sentence in every index, table of contents and grep
result. `REMOVED` with a Reason and a Migration, paired with `ADDED`, keeps the history legible: someone
who remembers the old name finds it, learns why it went, and is pointed at what replaced it.

### The guard had to learn removal, and the refusal is what made that happen

D322's tools implement `ADDED` and `MODIFIED` and REFUSE any other section rather than skipping it. This
change is the first to remove a requirement, so it hit that refusal immediately — which is exactly what
the refusal is for. Skipping the section would have silently dropped this change's deltas, reproducing
the bug the tools exist to prevent.

`REMOVED` also has to change the guard's meaning, not just its parser. A requirement withdrawn by a later
change must stop being demanded, or removal is impossible without switching the guard off — and a check
that must be switched off to do ordinary work does not survive contact with ordinary work. Order matters:
removed-then-re-added is required again, so the tools track the LAST operation per requirement rather
than a set of removals.

`RENAMED` is implemented at the same time even though this change does not use it. Leaving it as a loud
refusal would mean the next person to rename a requirement stops to build tooling, which is the tax that
makes people avoid the tool instead. It is covered by a fixture test rather than by use.

## Risks / Trade-offs

- **Getting a per-domain claim wrong reintroduces the overclaim D16 forbids.** Mitigated by requiring
  each claim to name its mechanism, and by every claim in the table above corresponding to a scenario in
  an existing capability that an integration test already exercises.
- **The file row will be read as a gap rather than a limit.** It is both, and the requirement says so:
  the design exists, the wiring does not, and the ordering constraint means even the wired version cannot
  block on a full classification.
- **Implementing `RENAMED` without a caller is speculative code.** Accepted, and bounded: it is a dozen
  lines and a fixture, and the alternative is a wall the next person hits.
