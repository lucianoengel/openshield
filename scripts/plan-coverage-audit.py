#!/usr/bin/env python3
"""Every declared capability must have a stated console classification.

WHY THIS EXISTS. The console plan was built from an information architecture — the
pages an analyst would want — rather than from the product's own declaration of what
it does. That is how a whole shipped domain (peer-UEBA) reached a finished-looking
plan with no surface, no ticket, and no row in any table: nobody thought of it, and
nothing was structured to notice.

`openspec/specs/` is the one inventory that is complete by construction: it is the
product's declaration of its own capabilities, it is maintained, and
`spec-store-audit.py` already guards its contents. So it is the right ground truth to
audit a plan against.

WHAT THIS CHECKS, AND WHAT IT DELIBERATELY DOES NOT. It checks that every capability
is CLASSIFIED — not that the classification is correct, and not that the surface is
good. Judgement stays with the reviewer; what the script removes is the ability to
skip a capability silently. That is the same bargain `doccheck` makes: it does not
judge a test, it fails when a named one stops existing.

Three classifications are legitimate, and one of them is "none":

  surface   — an operator surface exists or is ticketed. Name the ticket.
  internal  — no operator surface, deliberately. Name the reason.
  deferred  — needs one, not planned yet. Name the ticket that would close it.

An unclassified capability is the finding. "internal" with a reason is a fine answer;
"internal" is not, because an unexplained exemption is how a real gap hides.

NOT WIRED INTO CI, deliberately, and this is worth stating so nobody adds it out of
habit: the property can only go stale when a new capability spec is added, which is
not every commit. Run it when `openspec/specs/` gains a directory, or during a
planning pass. If the classification later proves contested and load-bearing, fold a
single assertion into `internal/doccheck` — which already runs and already reads
these documents — rather than adding a job.
"""

import os
import re
import sys

SPECS = "openspec/specs"
MATRIX = "docs/superpowers/specs/2026-07-31-console-ux-spec.md"
SECTION = r"## 13\. Capability coverage.*?(?=\n## )"
# A classification row: | `slug` | kind | detail |
ROW = re.compile(r"^\|\s*`([a-z0-9-]+)`\s*\|\s*(surface|internal|deferred)\s*\|\s*(.+?)\s*\|", re.M)


def main() -> int:
    declared = sorted(
        d for d in os.listdir(SPECS) if os.path.isdir(os.path.join(SPECS, d))
    )

    doc = open(MATRIX, encoding="utf-8").read()
    section = re.search(SECTION, doc, re.S)
    if not section:
        print(f"FAIL: no capability-coverage section found in {MATRIX}")
        return 1

    classified = {}
    for slug, kind, detail in ROW.findall(section.group(0)):
        classified[slug] = (kind, detail.strip())

    unclassified = [c for c in declared if c not in classified]
    stale = [c for c in classified if c not in declared]
    # An exemption with no reason is the failure this exists to prevent.
    unexplained = [
        c for c, (kind, detail) in classified.items() if not detail or detail == "—"
    ]

    ok = True
    if unclassified:
        ok = False
        print(f"UNCLASSIFIED ({len(unclassified)}) — declared capabilities with no row:")
        for c in unclassified:
            print(f"    {c}")
    if stale:
        ok = False
        print(f"\nSTALE ({len(stale)}) — rows for capabilities that no longer exist:")
        for c in stale:
            print(f"    {c}")
    if unexplained:
        ok = False
        print(f"\nUNEXPLAINED ({len(unexplained)}) — classified with no reason or ticket:")
        for c in unexplained:
            print(f"    {c}")

    counts = {}
    for kind, _ in classified.values():
        counts[kind] = counts.get(kind, 0) + 1
    summary = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
    print(
        f"\n{len(classified)} of {len(declared)} declared capabilities classified"
        f" ({summary})."
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
