#!/usr/bin/env bash
# Every package must be reachable from a shipped binary, or be on the list of ones that are not.
#
# WHY THIS IS A GUARD. This repository's most frequent defect is not a wrong line of code — it is a
# COMPLETE FEATURE THAT NOTHING STARTS. Package written, unit-tested, documented, described in the
# README, imported by no binary, and therefore unable to run in any deployment however configured.
# `internal/connectors/smtp` was exactly that: parser, capture listener with per-session ceilings,
# idle timeouts, concurrency cap, event producer, full tests — and no `cmd/` imported it while the
# README described live SMTP inspection. See docs/unwired-audit.md for the others.
#
# Unit tests cannot catch this, by construction: a package's tests import the package, so the tests
# pass whether or not anything else does. `go build ./...` cannot either — it compiles a library that
# nothing links. The only cheap signal is the IMPORT CLOSURE of ./cmd/..., which is what this checks.
#
# THE ALLOWLIST IS THE POINT. Some packages legitimately sit outside the closure — CI guards that are
# test-only, doc-only parent packages, spikes. Each needs a REASON here, so that the next entry is a
# deliberate decision instead of a silent one. If this script fails, the fix is usually to wire the
# package into a binary; adding a line below is correct only when the package genuinely is not
# shipped code, and the reason has to say which.
#
# PLATFORM CAVEAT, and it is a real one. The closure is computed for the HOST GOOS. A package wired
# only behind a `!linux` build tag (internal/connectors/filewatch, imported by
# cmd/openshield-engine/watcher_other.go) is invisible to `go list -deps` on Linux and would look
# unwired. Those are allowlisted with `platform:` and the importing file named, so the claim can be
# re-checked rather than taken on trust.
set -euo pipefail

cd "$(dirname "$0")/.."
MOD=github.com/lucianoengel/openshield

# Each entry: package path, then why it is outside the closure. Keep sorted.
allowed_reasons() {
	cat <<'EOF'
internal/agent                       doc-only: doc.go plus a structural test; no shipped code
internal/connectors                  doc-only: package documentation for the connector family
internal/connectors/filewatch        platform: wired by cmd/openshield-engine/watcher_other.go (!linux)
internal/doccheck                    test-only: the claim-surface / decision-register / spec-store CI guards
internal/enforcers                   doc-only: package documentation for the enforcer family
internal/fitness                     test-only: the architectural fitness and import-boundary guards
internal/packaging                   test-only: no implementation file at all, only a guard test
spikes/t002-gc-pause                 spike: the D19 GC-pause measurement, kept as the record of a decision
spikes/t005-fanotify                 spike: the T-005 fanotify capability probe, kept for the same reason
EOF
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

go list ./... | grep -v "/test/" | sort >"$tmp/all"
go list -deps ./cmd/... | grep "^$MOD" | sort -u >"$tmp/reachable"
comm -23 "$tmp/all" "$tmp/reachable" | sed "s|$MOD/||" | sort >"$tmp/outside"

allowed_reasons | awk 'NF {print $1}' | sort >"$tmp/allowed"

unexplained=$(comm -23 "$tmp/outside" "$tmp/allowed")
stale=$(comm -13 "$tmp/outside" "$tmp/allowed")

rc=0

if [ -n "$unexplained" ]; then
	cat >&2 <<'EOF'

A PACKAGE IS REACHABLE FROM NO SHIPPED BINARY.

Nothing under cmd/ imports it, directly or transitively, so it cannot run in any deployment however
configured. If it is a feature, it is not wired: find the binary it belongs in and import it there
(cmd/openshield-engine/smtpsource.go is the worked example of adding such a wire).

If it is genuinely not shipped code — a CI guard, a doc-only package, a spike, or wired only behind
a non-Linux build tag — add it to allowed_reasons() in this script WITH the reason, naming the
importing file for a platform-gated one.

Unexplained:
EOF
	echo "$unexplained" | sed 's/^/  /' >&2
	rc=1
fi

if [ -n "$stale" ]; then
	cat >&2 <<'EOF'

A STALE ALLOWLIST ENTRY. These are listed as outside the closure but are now reachable (or gone).
An allowlist that keeps entries it no longer needs stops being read, and the next real one hides in
it. Remove them from allowed_reasons():
EOF
	echo "$stale" | sed 's/^/  /' >&2
	rc=1
fi

if [ "$rc" -eq 0 ]; then
	printf 'ok: %s of %s packages are in the ./cmd/... closure; %s are outside it with a recorded reason\n' \
		"$(wc -l <"$tmp/reachable")" "$(wc -l <"$tmp/all")" "$(wc -l <"$tmp/outside")"
fi

exit "$rc"
