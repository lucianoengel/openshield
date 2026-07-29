#!/usr/bin/env bash
# No CI step may install a tool at an unpinned version.
#
# WHY THIS IS A GUARD. `go install some/tool@latest` in a workflow runs whatever that module publishes
# NEXT, inside CI, with the workflow's context — so a hijacked release executes on this project's
# infrastructure before any human sees the code. Two of these existed:
#
#   protoc-gen-go@latest  — the dangerous one. It GENERATES CODE THAT ENTERS THE BUILD, in the very job
#                           whose output is compared against the committed tree, so a compromised
#                           generator would emit its payload AND make the comparison agree with it.
#   govulncheck@latest    — added by a commit whose whole subject was supply-chain hygiene. A
#                           supply-chain risk introduced by a supply-chain check.
#
# The second one is why this is a script and not a resolution to be careful. It was written by someone
# actively thinking about supply chains, in the same hour, and it still happened.
#
# Unpinning also makes a security gate non-reproducible: a new release changes findings and fails the
# build with no code change, and a gate that breaks on its own schedule is one people learn to bypass.
#
# NOT CHECKED HERE, and named so the omission is a decision: `actions/*@v4`-style tags are mutable too —
# a SHA is the only real pin. This repo pins actions by major tag, which is the common posture and a
# separate call from the one this script enforces; changing it is an owner decision, not a guard.
set -euo pipefail

cd "$(dirname "$0")/.."

found=0
for f in .github/workflows/*.yml .github/workflows/*.yaml; do
	[ -f "$f" ] || continue
	# `run:` lines only — a comment discussing @latest is not an install.
	while IFS= read -r line; do
		echo "UNPINNED INSTALL in $f: ${line#"${line%%[![:space:]]*}"}"
		found=1
	done < <(grep -nE '^[[:space:]]*(run:|[[:space:]]+)' "$f" |
		grep -vE '^[0-9]+:[[:space:]]*#' |
		grep -E '(go install|npm i(nstall)? -g|pipx install|cargo install|uv tool install)[^#]*@latest')
done

if [ "$found" -ne 0 ]; then
	cat >&2 <<'EOF'

A CI step installs a tool at an unpinned version.

Pin it to an exact version:

    go install golang.org/x/vuln/cmd/govulncheck@v1.6.0

For a CODE GENERATOR, pin it to the runtime version in go.mod — a generator newer than the runtime it
generates against can emit code that runtime does not support, and the two drifting apart is a build
failure nobody will attribute correctly.
EOF
	exit 1
fi

echo "ok: every CI tool install is pinned"
