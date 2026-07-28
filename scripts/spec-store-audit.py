#!/usr/bin/env python3
"""Report requirements an archived change introduced that its capability spec no longer holds.

The spec store lost 186 of 558 requirements because a capability file was sometimes overwritten with
the delta being merged into it, and sometimes never merged at all. Neither failure produces an error,
so the loss is only visible by comparing the archive against the merged files — which is this.

Read-only. `scripts/spec-store-restore.py` does the repair; the guard in internal/doccheck keeps it
repaired. Exits non-zero when anything is missing, so it can gate as well as report.
"""

import glob
import os
import re
import sys
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The delta operations the tools implement. An unknown one is an ERROR, never a skip: refusing is what
# forced REMOVED and RENAMED to be implemented rather than silently dropped (D323), and skipping is how
# 170 requirements were lost (D322).
KNOWN_SECTIONS = {"ADDED", "MODIFIED", "REMOVED", "RENAMED"}


RENAME_FROM = re.compile(r"^\s*[-*]?\s*\**FROM\**:\s*`?### Requirement: (.+?)`?\s*$", re.I)
RENAME_TO = re.compile(r"^\s*[-*]?\s*\**TO\**:\s*`?### Requirement: (.+?)`?\s*$", re.I)


def parse_delta(path):
    """Yield (section, requirement_name) in file order, refusing an unknown section type.

    A RENAMED section names its requirements with FROM:/TO: lines rather than headings, so both forms
    are yielded: the old name as RENAMED_FROM and the new one as RENAMED_TO.
    """
    section = None
    for lineno, line in enumerate(open(path, encoding="utf-8"), 1):
        m = re.match(r"^## (\w+) Requirements", line)
        if m:
            section = m.group(1)
            if section not in KNOWN_SECTIONS:
                sys.exit(
                    f"{path}:{lineno}: section '## {section} Requirements' is not one this tool "
                    f"understands ({'/'.join(sorted(KNOWN_SECTIONS))}).\n"
                    "Refusing to continue: skipping a section is how the requirements were lost."
                )
            continue
        if section == "RENAMED":
            m = RENAME_FROM.match(line)
            if m:
                yield "RENAMED_FROM", m.group(1).strip()
                continue
            m = RENAME_TO.match(line)
            if m:
                yield "RENAMED_TO", m.group(1).strip()
                continue
        m = re.match(r"^### Requirement: (.+)$", line)
        if m:
            yield section, m.group(1).strip()


def capability_headers(path):
    if not os.path.exists(path):
        return None
    return {
        m.group(1).strip()
        for m in re.finditer(r"^### Requirement: (.+)$", open(path, encoding="utf-8").read(), re.M)
    }


def latest_operations(deltas):
    """Return {(capability, requirement): (operation, change)} after replaying the archive in order.

    The LAST operation wins, which is the only rule that makes removal work. Tracking a set of removed
    requirements instead would be wrong the moment one is removed and later added again — and a check
    that cannot express "we retired this, then changed our minds" is one people route around.
    """
    state = {}
    for d in deltas:
        cap = d.split("/specs/")[1].split("/")[0]
        is_archived = "/archive/" in d
        change = (d.split("/archive/")[1] if is_archived else d.split("/changes/")[1]).split("/")[0]
        # An ACTIVE change is a proposal: honour it only where it RELAXES. Its REMOVED entries count (or
        # retiring a requirement keeps the gate red for the life of the change that retires it); its
        # ADDED entries do not, because the sync happens at archive and demanding them earlier would
        # make every proposal red from the moment it is written.
        active = not is_archived
        for op, name in parse_delta(d):
            if op == "RENAMED_FROM":
                state[(cap, name)] = ("REMOVED", change)
            elif op == "RENAMED_TO":
                if not active:
                    state[(cap, name)] = ("ADDED", change)
            elif active and op != "REMOVED":
                continue
            else:
                state[(cap, name)] = (op, change)
    return state


def main():
    deltas = sorted(glob.glob(os.path.join(REPO, "openspec/changes/archive/*/specs/*/spec.md")))
    if not deltas:
        sys.exit("no archived deltas found — is this being run outside the repo?")
    # ACTIVE changes count as the newest operations. A change that RETIRES a requirement only reaches
    # the archive at its last step, so without this the audit is red for the whole life of the work it
    # exists to permit — and a check that fails throughout ordinary work gets switched off.
    deltas += sorted(
        p for p in glob.glob(os.path.join(REPO, "openspec/changes/*/specs/*/spec.md"))
        if "/archive/" not in p
    )

    state = latest_operations(deltas)
    missing = defaultdict(list)
    in_force = defaultdict(set)
    caps = {cap for cap, _ in state}

    for (cap, name), (op, change) in state.items():
        if op == "REMOVED":
            continue  # deliberately retired — absence is correct, not a loss
        in_force[cap].add(name)
        have = capability_headers(os.path.join(REPO, "openspec/specs", cap, "spec.md"))
        if have is None or name not in have:
            missing[cap].append((name, change))

    total = sum(len(v) for v in in_force.values())
    gone = sum(len(v) for v in missing.values())
    retired = sum(1 for op, _ in state.values() if op == "REMOVED")

    for cap in sorted(missing):
        print(f"\n{cap}  —  {len(missing[cap])} missing of {len(in_force[cap])}")
        for name, change in sorted(missing[cap]):
            print(f"    {name}\n        introduced by {change}")

    print(
        f"\n{gone} of {total} in-force archived requirements are absent from their capability file "
        f"({len(missing)} capabilities damaged, {len(caps) - len(missing)} intact; "
        f"{retired} deliberately retired and correctly absent)."
    )
    return 1 if gone else 0


if __name__ == "__main__":
    sys.exit(main())
