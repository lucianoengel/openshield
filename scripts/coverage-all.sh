#!/usr/bin/env bash
# The WHOLE coverage picture: unit + integration + privileged, merged.
#
# WHY THIS EXISTS AND scripts/coverage-integration.sh IS NOT ENOUGH. That one measures what the integration
# suite executes in the real binaries, which is a genuinely useful question and a badly misleading answer if
# it is read as "how much of this code is tested". Measured on the same tree:
#
#   integration only          55.2%,  4 packages at 0%
#   unit + integration        70.2%,  0 packages at 0%
#   + privileged (this)       71.1%
#
# The overall move from the privileged set is small. The PER-PACKAGE move is not, and it lands entirely on
# the code that matters most:
#
#   internal/agent/openmon     11.2% -> 85.0%
#   internal/agent/execmon     30.7% -> 80.4%
#   internal/dnsredirect       39.3% -> 77.8%
#   internal/agent/watchdog    66.7% -> 90.9%
#   cmd/openshield-agent       18.6% -> 51.7%
#
# Those are the fanotify permission gate, the exec gate and the watchdog — the components whose failure
# wedges a machine. Reporting them in the teens because the measurement could not reach them is worse than
# not measuring: it invites exactly the "well, it's gated" shrug that let twelve of those tests run in no
# automated gate at all for months.
#
# HONEST LIMITS, because a coverage number invites over-reading:
#   - Statement coverage is not path coverage. Every line of a function can run without its error branch.
#   - This is a work list, not a grade.
#   - test/integration's own figure (~15%) is the harness measuring itself. Ignore it.
set -euo pipefail

cd "$(dirname "$0")/.."
MOD=github.com/lucianoengel/openshield
OUT=${1:-$(mktemp -d -t openshield-coverage-all-XXXXXX)}
PRIV=${OPENSHIELD_PRIVILEGED_COVDATA:-}
mkdir -p "$OUT/unit" "$OUT/merged"
echo "output: $OUT"

echo
echo "== unit tests =="
# OPENSHIELD_REQUIRE_POSTGRES=1 IS NOT OPTIONAL HERE, and leaving it out produced a wrong headline.
#
# Most of internal/controlplane's tests need a database and SKIP without one. Measured with Postgres down,
# that package ran in 0.9s instead of ~90s and contributed 6% — and the merged report then named it, at
# 49.6%, as one of two packages "with no excuse". It was an artefact of the measurement, not a gap in the
# tests, and it is the same mistake this whole exercise kept finding elsewhere: a dependency absent, the
# result read as "untested".
#
# With the flag, a missing database is a hard FAILURE rather than a silent skip. A coverage run that cannot
# reach its dependencies must say so, not quietly report a smaller number.
if ! command -v podman >/dev/null 2>&1 || ! (exec 3<>/dev/tcp/127.0.0.1/55432) 2>/dev/null; then
	cat >&2 <<'EOF'

== NO DATABASE ON 127.0.0.1:55432 ==

internal/controlplane, internal/store and internal/xdr need one; without it their tests skip and this run
will understate them badly (controlplane drops from ~90s of tests to under a second). Start one first:

    podman run -d --rm --name openshield-dev-pg \
      -e POSTGRES_USER=openshield -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=openshield \
      -p 127.0.0.1:55432:5432 docker.io/library/postgres:16

EOF
	exit 1
fi
exec 3<&- 2>/dev/null || true
OPENSHIELD_REQUIRE_POSTGRES=1 go test -cover -coverpkg=./... ./... -args -test.gocoverdir="$OUT/unit" >"$OUT/unit.log" 2>&1 || {
	echo "unit tests reported failures (see $OUT/unit.log); continuing to measure what did run" >&2
}

echo
echo "== integration suite, against the real binaries =="
./scripts/coverage-integration.sh "$OUT/int" >"$OUT/int.log" 2>&1 || {
	echo "integration run reported failures (see $OUT/int.log); continuing" >&2
}

inputs="$OUT/unit,$OUT/int/covdata"

echo
if [ -n "$PRIV" ] && [ -d "$PRIV" ] && [ "$(find "$PRIV" -type f | wc -l)" -gt 0 ]; then
	echo "== privileged coverage included from $PRIV =="
	inputs="$inputs,$PRIV"
else
	# LOUD, because omitting it does not just lower the number — it lowers it SPECIFICALLY on the fanotify
	# gate, the exec gate and the watchdog, by four to seven times. A reader who does not know that will
	# conclude the most dangerous code in the product is the least tested, and the opposite is true.
	cat >&2 <<'EOF'

== PRIVILEGED COVERAGE MISSING — the figure below UNDERSTATES the security-critical packages ==

The fanotify open gate, the exec gate, the DNS redirect and the clipboard mediator need root (CAP_SYS_ADMIN)
or a real X display, so their tests do not run here. Without them internal/agent/openmon reads ~11% instead
of ~85%, and cmd/openshield-agent ~19% instead of ~52%.

To include them, run the privileged binaries as root (a VM, or CI's kernel-enforcement job) with
-test.gocoverdir pointing at a directory, then re-run this with:

    OPENSHIELD_PRIVILEGED_COVDATA=<that directory> scripts/coverage-all.sh

EOF
fi

go tool covdata merge -i="$inputs" -o="$OUT/merged"
go tool covdata textfmt -i="$OUT/merged" -o="$OUT/merged.txt"

echo
echo "== per package, lowest first =="
go tool covdata percent -i="$OUT/merged" 2>/dev/null | sed "s|$MOD/||" |
	awk '{gsub(/%/,"",$3); if ($3 ~ /^[0-9.]+$/) print $3, $1}' | sort -n >"$OUT/bypkg.txt"
if [ ! -s "$OUT/bypkg.txt" ]; then
	# An empty work list reads as "everything is covered", so it is an error rather than a report.
	echo "PARSE PRODUCED NO ROWS from a non-empty merge — fix the parse rather than trusting this" >&2
	exit 1
fi

# GENERATED PACKAGES ARE SEPARATED, NOT DELETED.
#
# internal/core/corev1 is eleven .pb.go files and nothing else. Its 57.2% measures how much of protoc's
# marshalling boilerplate a test happened to walk through, which is not a fact about this project's testing
# — and it appeared on a published work list as though it were, directly under two packages that genuinely
# needed tests. Raising it would mean writing tests for generated code to move a number.
#
# They are still PRINTED, below the work list. Dropping them silently would be its own dishonesty: the next
# person to compare this output against `go tool covdata percent` would find rows missing with no
# explanation, and a filter nobody can see is indistinguishable from a filter that is wrong.
: >"$OUT/generated.txt"
: >"$OUT/worklist.txt"
while read -r pct pkg; do
	dir="${pkg#"$MOD"/}"
	if [ -d "$dir" ] && [ -z "$(find "$dir" -maxdepth 1 -name '*.go' ! -name '*.pb.go' ! -name '*_test.go' -print -quit)" ] &&
		[ -n "$(find "$dir" -maxdepth 1 -name '*.pb.go' -print -quit)" ]; then
		printf '%s %s\n' "$pct" "$pkg" >>"$OUT/generated.txt"
	else
		printf '%s %s\n' "$pct" "$pkg" >>"$OUT/worklist.txt"
	fi
done <"$OUT/bypkg.txt"

awk '{printf "%6s%%  %s\n", $1, $2}' "$OUT/worklist.txt"
if [ -s "$OUT/generated.txt" ]; then
	echo
	echo "-- generated code, reported but NOT a work list (coverage here measures protoc's output) --"
	awk '{printf "%6s%%  %s\n", $1, $2}' "$OUT/generated.txt"
fi

echo
echo "== summary =="
go tool cover -func="$OUT/merged.txt" | tail -1
awk '$1<50{a++} $1>=50&&$1<70{b++} $1>=70&&$1<85{c++} $1>=85{d++}
     END{printf "under 50%%: %d   50-70%%: %d   70-85%%: %d   85%%+: %d   (of %d hand-written packages)\n",a+0,b+0,c+0,d+0,NR}' "$OUT/worklist.txt"
echo "work list: $OUT/worklist.txt (all packages: $OUT/bypkg.txt)"
