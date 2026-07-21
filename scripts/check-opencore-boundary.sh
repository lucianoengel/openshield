#!/usr/bin/env bash
# Open code must not import enterprise code (T-021, D21).
#
# Open-core only works if the open distribution builds without the managed code.
# The boundary is ONE-WAY: enterprise code may build on the open core, but no
# open package may import anything under internal/enterprise/... — or the open
# build would break, or silently pull closed code into the open artifact.
#
# None of that enterprise code exists yet. That is the point of drawing the line
# now (D21): the first commit of managed code must land on the correct side of a
# line that already exists. Because a check with nothing to guard passes
# trivially, `--selftest` plants a violation in a temp module and proves the
# detection fires — an unproven boundary check is meaningless green.
set -euo pipefail

RESERVED_SUFFIX="/internal/enterprise"

# detect MODULE ROOT: fails (non-empty output) if any OPEN package depends on a
# package under <module><RESERVED_SUFFIX>. Runs in the current directory's module.
detect() {
  local module
  module="$(go list -m 2>/dev/null)"
  if [ -z "$module" ]; then
    echo "check-opencore-boundary: not in a Go module" >&2
    return 2
  fi
  local reserved="${module}${RESERVED_SUFFIX}"

  local violations=""
  # Every package EXCEPT those inside the reserved tree.
  local pkgs
  pkgs="$(go list ./... 2>/dev/null | grep -v -E "${reserved}(/|$)" || true)"
  for pkg in $pkgs; do
    if go list -deps "$pkg" 2>/dev/null | grep -q -E "^${reserved}(/|$)"; then
      violations="${violations}${pkg}\n"
    fi
  done
  if [ -n "$violations" ]; then
    echo -e "$violations"
    return 1
  fi
  return 0
}

selftest() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  (
    cd "$tmp"
    cat > go.mod <<'GOMOD'
module example.com/selftest

go 1.26
GOMOD
    mkdir -p internal/enterprise/secret openpkg
    cat > internal/enterprise/secret/secret.go <<'GO'
package secret

func Managed() string { return "managed" }
GO
    # An OPEN package that (wrongly) imports the reserved enterprise tree.
    cat > openpkg/open.go <<'GO'
package openpkg

import "example.com/selftest/internal/enterprise/secret"

var _ = secret.Managed
GO
    if detect >/dev/null 2>&1; then
      echo "SELFTEST FAILED: the check did NOT flag an open->enterprise import — the boundary" >&2
      echo "guard is not actually detecting violations, so its green means nothing." >&2
      return 1
    fi
    return 0
  )
}

case "${1:-check}" in
  --selftest)
    if selftest; then
      echo "ok: open-core boundary check self-test passed (a planted violation was detected)"
    else
      exit 1
    fi
    ;;
  check)
    if hits="$(detect)"; then
      echo "ok: no open package imports internal/enterprise"
    else
      status=$?
      if [ "$status" = "1" ]; then
        echo "FAIL: open packages import enterprise code they must not (T-021, D21):" >&2
        echo -e "$hits" | sed 's/^/  /' >&2
        echo >&2
        echo "The boundary is one-way: enterprise may build on the open core, not the reverse." >&2
      fi
      exit "$status"
    fi
    ;;
  *)
    echo "usage: $0 [check|--selftest]" >&2
    exit 2
    ;;
esac
