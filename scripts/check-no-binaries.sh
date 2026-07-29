#!/usr/bin/env bash
# No compiled executable may be tracked in this repository.
#
# WHY THIS IS A GUARD AND NOT A ONE-OFF CLEANUP. Seven binaries — 157 MB — were committed to the
# public repo in July 2026 and never updated, so a clone handed anyone official-looking executables
# for a security product that were a week stale. `go build ./cmd/openshield-engine/` writes its output
# into the working directory, which is an ordinary thing to do and leaves an artifact indistinguishable
# from a source file to `git add -A`. It will happen again; the point is that it fails loudly when it
# does.
#
# The distribution story is `make release`: reproducible builds with a signed manifest and a signed
# SBOM (PLAT-6). A binary that arrives by `git clone` has none of that — no digest, no signature, no
# statement of what it was built from. Shipping one alongside the tooling that exists to prevent
# exactly that is the contradiction this refuses.
#
# Only files at or above minBytes are inspected: no Go binary is smaller, and it keeps the check to a
# handful of reads rather than one per tracked file.
set -euo pipefail

cd "$(dirname "$0")/.."

min_bytes=65536
found=0

while IFS= read -r -d '' f; do
	[ -f "$f" ] || continue
	size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
	[ "$size" -ge "$min_bytes" ] || continue

	# Executable magic: ELF, Mach-O (32/64, both endiannesses), a Mach-O universal binary, and PE/COFF
	# — whose header varies past the leading "MZ", so only those two bytes are matched.
	magic=$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')
	case "$magic" in
	7f454c46 | feedface | cefaedfe | feedfacf | cffaedfe | cafebabe | 4d5a*)
		echo "TRACKED BINARY: $f ($size bytes, magic $magic)"
		found=1
		;;
	esac
done < <(git ls-files -z)

if [ "$found" -ne 0 ]; then
	cat >&2 <<'EOF'

A compiled executable is tracked in this repository.

Building a single command writes its binary into the working directory:

    go build ./cmd/openshield-engine/    # writes ./openshield-engine

`git add -A` then sweeps it in. Remove it from the index and let .gitignore hold it:

    git rm --cached <file>

Distribute binaries through `make release`, which signs a manifest and an SBOM over them. A binary
that arrives by `git clone` carries no digest, no signature, and no statement of its provenance.
EOF
	exit 1
fi

echo "ok: no compiled executables are tracked"
