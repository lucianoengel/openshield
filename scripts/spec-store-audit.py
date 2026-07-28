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
# The two section types this archive actually contains. Anything else must STOP the tools rather than
# be skipped: quietly ignoring a section is the exact behaviour that emptied control-plane/spec.md.
KNOWN_SECTIONS = {"ADDED", "MODIFIED"}


def parse_delta(path):
    """Yield (section, requirement_name) in file order, refusing an unknown section type."""
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


def main():
    deltas = sorted(glob.glob(os.path.join(REPO, "openspec/changes/archive/*/specs/*/spec.md")))
    if not deltas:
        sys.exit("no archived deltas found — is this being run outside the repo?")

    missing = defaultdict(list)  # capability -> [(requirement, change)]
    seen = defaultdict(set)      # capability -> {requirement}
    caps = set()

    for d in deltas:
        cap = d.split("/specs/")[1].split("/")[0]
        change = d.split("/archive/")[1].split("/")[0]
        caps.add(cap)
        have = capability_headers(os.path.join(REPO, "openspec/specs", cap, "spec.md"))
        for _, name in parse_delta(d):
            seen[cap].add(name)
            if have is None or name not in have:
                # Report a requirement once, against the LAST change that introduced it — an
                # ADDED-then-MODIFIED chain is one missing requirement, not three.
                missing[cap] = [x for x in missing[cap] if x[0] != name] + [(name, change)]

    total = sum(len(v) for v in seen.values())
    gone = sum(len(v) for v in missing.values())
    for cap in sorted(missing):
        print(f"\n{cap}  —  {len(missing[cap])} missing of {len(seen[cap])}")
        for name, change in missing[cap]:
            print(f"    {name}\n        introduced by {change}")

    print(
        f"\n{gone} of {total} archived requirements are absent from their capability file "
        f"({len(missing)} capabilities damaged, {len(caps) - len(missing)} intact)."
    )
    return 1 if gone else 0


if __name__ == "__main__":
    sys.exit(main())
