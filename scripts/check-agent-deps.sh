#!/usr/bin/env bash
# The privileged agent must not be able to parse attacker-controlled bytes.
#
# It holds CAP_SYS_ADMIN and answers fanotify permission events. A parser memory
# bug in a process with that privilege is host compromise — the failure mode
# behind repeated RCEs in comparable security products (e.g. ClamAV
# CVE-2025-20260, a PDF-parser heap overflow in a privileged daemon).
#
# This is why the two halves are separate BINARIES. One binary with a --worker
# flag would carry the parsers in its dependency graph regardless of which code
# path ran, and this check would prove nothing.
set -euo pipefail

PRIVILEGED_PKG="./cmd/openshield-agent"

# Parsers and decoders that must never appear in the privileged binary.
# archive/* and compress/* handle attacker-controlled containers; encoding/*
# covers the structured-format decoders. text/template and html/template are
# here because template execution on untrusted input is its own hazard.
BANNED_RE='^(archive/|compress/|encoding/(json|xml|csv|asn1|gob|pem)|text/template|html/template|image/|github.com/.*(pdf|docx|tika|ocr))'

deps="$(go list -deps "$PRIVILEGED_PKG" 2>/dev/null || true)"
if [ -z "$deps" ]; then
  echo "check-agent-deps: could not compute dependencies for $PRIVILEGED_PKG" >&2
  exit 2
fi

if hits="$(echo "$deps" | grep -E "$BANNED_RE" || true)"; [ -n "$hits" ]; then
  echo "FAIL: the privileged agent depends on parsers it must never hold:" >&2
  echo "$hits" | sed 's/^/  /' >&2
  echo >&2
  echo "Content parsing belongs in cmd/openshield-worker, which is unprivileged." >&2
  echo "The privileged process does bookkeeping only (D13)." >&2
  exit 1
fi

echo "ok: privileged agent has no parser dependencies"
