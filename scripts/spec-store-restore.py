#!/usr/bin/env python3
"""Restore requirements the spec store lost, by replaying archived deltas into capability files.

ADDITIVE ONLY, and that is the important property. A capability file may hold requirements with no
archived source — 28 of them do, authored directly rather than through a change — so regenerating a
file from its archive would delete them. A repair that loses requirements while fixing lost
requirements is not a repair. This appends what is missing and touches nothing else, which also makes
the diff pure addition and therefore reviewable.

Deltas are replayed in chronological order (archive directories are date-prefixed) with the later
occurrence winning, so an ADDED later revised by a MODIFIED restores as the revision.

Requirements already present under the same heading are LEFT ALONE even when the archive holds a newer
body. Those are reported at the end and left for a deliberate pass: rewriting requirement bodies inside
a change described as additive would be a content change in disguise.

Run with --dry-run to see what would change. Re-runnable: a second run is a no-op.
"""

import glob
import os
import re
import sys
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOWN_SECTIONS = {"ADDED", "MODIFIED"}


def split_requirements(text, source):
    """Return [(name, block)] for each requirement in a spec or delta file.

    A block runs from its heading to the next heading (or EOF), so scenarios travel with the
    requirement they belong to.
    """
    out = []
    positions = [m.start() for m in re.finditer(r"^### Requirement: ", text, re.M)]
    for i, start in enumerate(positions):
        end = positions[i + 1] if i + 1 < len(positions) else len(text)
        block = text[start:end].rstrip()
        name = block.split("\n", 1)[0][len("### Requirement: "):].strip()
        out.append((name, block))
    _refuse_unknown_sections(text, source)
    return out


def _refuse_unknown_sections(text, source):
    for lineno, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^## (\w+) Requirements", line)
        if m and m.group(1) not in KNOWN_SECTIONS:
            sys.exit(
                f"{source}:{lineno}: '## {m.group(1)} Requirements' is not a section this tool "
                f"understands ({'/'.join(sorted(KNOWN_SECTIONS))}).\n"
                "Refusing to continue rather than skipping it — skipping is how the requirements "
                "were lost in the first place."
            )


def _strip_marker(block):
    return re.sub(r"\n*<!-- restored from [^>]*-->\s*$", "", block).strip()


def repair_structure(path, dry):
    """Reinstate the '## Requirements' heading a clobbering sync removed.

    A delta file is a list of '## ADDED Requirements' sections; a capability file is '## Purpose'
    followed by '## Requirements'. Overwriting the second with the first therefore destroyed the
    document structure as well as the content, and `openspec validate` has been failing on 37 of 75
    capabilities ever since — which is why nobody noticed the requirements were gone either. A store
    whose validator has been red for weeks reports nothing when it goes redder.

    Purely positional: the heading goes after the Purpose (or after the title) and before the first
    requirement. No text is authored and none is moved.
    """
    text = open(path, encoding="utf-8").read()
    if re.search(r"^## Requirements\s*$", text, re.M):
        return False
    m = re.search(r"^### Requirement: ", text, re.M)
    if not m:
        return False
    new = text[:m.start()].rstrip() + "\n\n## Requirements\n\n" + text[m.start():]
    if not dry:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new)
    return True


def main():
    dry = "--dry-run" in sys.argv
    caps = sorted({
        p.split("/specs/")[1].split("/")[0]
        for p in glob.glob(os.path.join(REPO, "openspec/changes/archive/*/specs/*/spec.md"))
    })

    restored_total = 0
    touched = []
    stale = []          # present under the same heading, older body than the archive
    collisions = []     # a heading introduced by more than one change

    for cap in caps:
        main_path = os.path.join(REPO, "openspec/specs", cap, "spec.md")
        deltas = sorted(glob.glob(os.path.join(REPO, f"openspec/changes/archive/*/specs/{cap}/spec.md")))

        # Chronological replay: later wins. `sorted` is chronological because the directories are
        # date-prefixed, and same-day changes keep a stable order.
        latest, origin, times_seen = {}, {}, defaultdict(int)
        for d in deltas:
            change = d.split("/archive/")[1].split("/")[0]
            for name, block in split_requirements(open(d, encoding="utf-8").read(), d):
                if name in latest and latest[name] != block:
                    times_seen[name] += 1
                latest[name], origin[name] = block, change
        collisions += [(cap, n) for n, c in times_seen.items() if c]

        current_text = open(main_path, encoding="utf-8").read() if os.path.exists(main_path) else ""
        present = dict(split_requirements(current_text, main_path))

        additions = []
        for name in latest:  # dict order == first-seen order == chronological
            if name in present:
                # Compare WITHOUT the provenance marker this script appends, or a second run reports
                # every requirement it restored as stale against the archive it came from.
                if _strip_marker(present[name]) != _strip_marker(latest[name]):
                    stale.append((cap, name))
                continue
            additions.append((name, latest[name], origin[name]))

        if not additions:
            continue

        parts = [current_text.rstrip()] if current_text.strip() else []
        for name, block, change in additions:
            parts.append(f"{block}\n\n<!-- restored from {change} -->")
        new_text = "\n\n".join(parts).rstrip() + "\n"

        touched.append((cap, len(additions)))
        restored_total += len(additions)
        if not dry:
            os.makedirs(os.path.dirname(main_path), exist_ok=True)
            with open(main_path, "w", encoding="utf-8") as f:
                f.write(new_text)

    # Structural repair runs over EVERY capability, not only the damaged ones: a file can have kept its
    # requirements and still have lost its headings.
    structural = [
        p.split("/")[-2] for p in sorted(glob.glob(os.path.join(REPO, "openspec/specs/*/spec.md")))
        if repair_structure(p, dry)
    ]

    verb = "would restore" if dry else "restored"
    for cap, n in touched:
        print(f"  {cap:34s} {verb} {n}")
    print(f"\n{verb} {restored_total} requirements across {len(touched)} capabilities "
          f"({len(caps) - len(touched)} untouched).")

    if structural:
        print(f"\n{'would reinstate' if dry else 'reinstated'} the '## Requirements' heading in "
              f"{len(structural)} capabilities.")

    missing_purpose = [
        p.split("/")[-2] for p in sorted(glob.glob(os.path.join(REPO, "openspec/specs/*/spec.md")))
        if not re.search(r"^## Purpose\s*$", open(p, encoding="utf-8").read(), re.M)
    ]
    if missing_purpose:
        print(f"\nNO PURPOSE SECTION — {len(missing_purpose)} capabilities. NOT written here: a purpose "
              "is authored prose, and the archived proposals carry a description of the CHANGE, not of "
              "the capability (control-plane's earliest line describes alert notification). Generating "
              "from those would put a confidently wrong sentence at the top of a spec.")
        print("    " + ", ".join(missing_purpose))

    if stale:
        print(f"\nPRESENT BUT STALE — {len(stale)} requirements carry an older body than the archive's "
              "latest version. LEFT UNCHANGED, deliberately: rewriting them is a content change and "
              "belongs in its own pass.")
        for cap, name in stale:
            print(f"    {cap}: {name}")
    if collisions:
        print(f"\nREVISED IN MORE THAN ONE CHANGE — {len(collisions)} requirements; the latest body won.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
