#!/usr/bin/env bash
# Measure what the INTEGRATION SUITE actually executes, in the REAL shipped binaries.
#
# WHY THIS EXISTS. `go test -cover` measures a package's own unit tests. It says nothing about the
# question that matters here: when the integration suite starts `openshield-engine` as a real
# process against real Postgres and NATS, which lines of which packages actually run? A package can
# sit at 90% unit coverage and be reachable from no binary at all — that is the "unwired feature"
# failure this repository has hit repeatedly (docs/unwired-audit.md), and unit coverage cannot see it.
#
# HOW. `go build -cover -coverpkg=./...` produces instrumented binaries; each writes a coverage
# profile into $GOCOVERDIR on exit. The suite already has the seam needed to use them:
# OPENSHIELD_INTEGRATION_BIN_DIR makes the harness use pre-built binaries instead of building its
# own, and children inherit GOCOVERDIR through os.Environ(). The harness's SIGTERM-first shutdown is
# what makes this work at all — a SIGKILLed process flushes no profile.
#
# TWO NUMBERS, AND THE SECOND IS THE IMPORTANT ONE:
#
#   1. Statement coverage per package — the work list. Low means the suite drives little of it.
#   2. Packages UNREACHABLE from ./cmd/... — computed statically, no run needed. This is stronger
#      than "0% covered": it means no shipped binary can reach the code however it is configured.
#      A legitimate entry here is test-only (internal/fitness, internal/doccheck), doc-only, a
#      spike, or platform-gated behind a !linux tag. Anything else is a feature nobody can run.
#
# HONEST LIMITS, stated because a coverage number invites over-reading:
#   - Instrumentation slows the binaries. Timing-sensitive tests can fail under it and pass in CI;
#     a failure here is a signal to investigate, not proof of a product bug.
#   - Statement coverage is not path coverage. 100% of a function's lines can run without ever
#     taking its error branch.
#   - This measures the integration suite alone, deliberately. Unit tests cover much more; the
#     point of this script is precisely to find what only unit tests hold up.
#
# Usage: scripts/coverage-integration.sh [output-dir]
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
MOD=github.com/lucianoengel/openshield

OUT=${1:-$(mktemp -d -t openshield-coverage-XXXXXX)}
mkdir -p "$OUT/bin" "$OUT/covdata"
echo "output: $OUT"

# ---- part 2 first, because it needs no run and cannot be invalidated by a flaky test ----
echo
echo "== packages unreachable from any shipped binary =="
go list ./... | grep -v "/test/" | sort >"$OUT/all.txt"
go list -deps ./cmd/... | grep "^$MOD" | sort -u >"$OUT/reachable.txt"
comm -23 "$OUT/all.txt" "$OUT/reachable.txt" | sed "s|$MOD/||" >"$OUT/unreachable.txt"
printf 'packages: %s total, %s in the ./cmd/... closure, %s unreachable\n' \
	"$(wc -l <"$OUT/all.txt")" "$(wc -l <"$OUT/reachable.txt")" "$(wc -l <"$OUT/unreachable.txt")"
cat "$OUT/unreachable.txt"
echo "(NOTE: computed for THIS GOOS. A package wired only behind a !linux tag appears here on"
echo " Linux and is not necessarily unwired — check for a *_other.go / *_windows.go importer.)"

# ---- part 1: instrumented run ----
echo
echo "== building instrumented binaries =="
go build -cover -coverpkg=./... -o "$OUT/bin" ./cmd/...

echo
echo "== running the integration suite against them =="
set +e
OPENSHIELD_REQUIRE_POSTGRES=1 \
	OPENSHIELD_INTEGRATION_BIN_DIR="$OUT/bin" \
	GOCOVERDIR="$OUT/covdata" \
	go test -tags integration -count=1 -timeout 40m ./test/integration/ >"$OUT/suite.log" 2>&1
suite_rc=$?
set -e
echo "suite exit: $suite_rc (log: $OUT/suite.log)"
if [ "$suite_rc" -ne 0 ]; then
	echo "--- failures:"
	grep -E '^(---|\s+---) FAIL' "$OUT/suite.log" | head -20 || true
	echo "(see the limits note in this script's header before treating a failure as a product bug)"
fi

profiles=$(find "$OUT/covdata" -type f | wc -l)
if [ "$profiles" -eq 0 ]; then
	echo "NO COVERAGE PROFILES WERE WRITTEN. The measurement did not happen; the numbers below" >&2
	echo "would be zero for that reason and not because nothing ran. Refusing to report them." >&2
	exit 1
fi
echo "coverage profiles collected: $profiles"

# ---- report ----
echo
echo "== per-package statement coverage, lowest first =="
# `covdata percent` prints e.g. `<pkg>	coverage: 26.3% of statements`. The percentage is field 3.
# It was field $NF once in an ad-hoc version of this analysis, which is the word "statements" — so
# every filter matched nothing and the report was silently empty. Hence: parse field 3, and assert
# below that the parse produced numbers at all.
go tool covdata percent -i="$OUT/covdata" 2>/dev/null |
	sed "s|$MOD/||" |
	awk '{gsub(/%/,"",$3); if ($3 ~ /^[0-9.]+$/) print $3, $1}' |
	sort -n >"$OUT/bypkg.txt"

if [ ! -s "$OUT/bypkg.txt" ]; then
	echo "PARSE PRODUCED NO ROWS from a non-empty profile set. The report format changed; fix the" >&2
	echo "parse rather than trusting an empty work list — an empty list reads as 'all covered'." >&2
	exit 1
fi

awk '{printf "%6s%%  %s\n", $1, $2}' "$OUT/bypkg.txt"

echo
echo "== summary =="
go tool covdata percent -i="$OUT/covdata" -pkg=./... 2>/dev/null | tail -1 || true
awk '$1 == 0   {n++} END {printf "packages at 0%%:        %d\n", n+0}' "$OUT/bypkg.txt"
awk '$1 < 25   {n++} END {printf "packages under 25%%:    %d\n", n+0}' "$OUT/bypkg.txt"
awk '{s+=$1; n++} END {if (n) printf "packages measured:     %d\n", n}' "$OUT/bypkg.txt"
echo
echo "work list written to $OUT/bypkg.txt; unreachable set to $OUT/unreachable.txt"
