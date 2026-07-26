## Why

Configuration is ~50 `os.Getenv` calls spread across `cmd/openshield-server` and `cmd/openshield-gateway`,
each with its own inline default and its own idea of what a bad value means. A typo in
`OPENSHIELD_CORRELATE_INTERVAL` silently disables scheduled correlation; a malformed duration falls back to
a default without saying so; and there is no way to ask a running binary what configuration it is actually
honouring.

**The constraint that shapes this design: configuration will eventually be set mostly in the UI (PLAT-1).**
That makes an env-only config layer the wrong thing to build — not because env is bad, but because a config
layer with no machine-readable schema forces a future UI to maintain its own list of fields, which drifts
from what the binary actually reads. The drift is silent and the symptom is a form that saves a setting the
server ignores.

## What Changes

- **One typed `Config` struct** per binary, with every field declaring its key, kind, default, description
  and validation in one place — replacing the scattered `os.Getenv` + inline-default pattern.
- **A schema DERIVED from that struct** (`Describe()`), not maintained beside it. This is the UI's data
  source, and deriving it is what makes a future form structurally unable to offer a field the binary does
  not read.
- **Secrets are never readable back.** A field marked secret reports `set` / `unset` and never its value —
  in the descriptor, in the `config` subcommand, and in any future API. A UI that can render a token into a
  form field is an exfiltration path.
- **Field-scoped validation errors**: every problem names its field, the offending value and the
  constraint, and *all* problems are reported together rather than failing on the first. A UI shows them
  inline; an operator fixes them in one pass instead of one boot at a time.
- **Fail-fast at boot** on an invalid value, instead of today's silent fallback to a default.
- **A `Source` interface** with explicit precedence (env over file over default), so a DB-backed source
  written by the UI can be added later without touching a single call site.
- **`openshield-server config`**: prints the schema and the effective values (secrets redacted) — the
  operator-visible half now, and the same data the UI will render later.

## Capabilities

### New Capabilities
- `typed-config`: a declared, validated, introspectable configuration model with layered sources and
  redacted secrets.

## Impact

- **New code**: `internal/config` (fields, sources, validation, descriptor).
- **Changed**: `cmd/openshield-server` reads config through it; a `config` subcommand.
- **No migration, no proto change, no new dependency** (no reflection-tag library — fields are declared
  explicitly, see the design).
- **Backward compatible**: every existing environment variable keeps its name, meaning and default.
- **Honest scope**: this increment covers the **server**; the gateway and agent binaries are a follow-up
  that reuses the same package. **No UI and no write path** — nothing here accepts configuration over the
  network, and the `Source` interface is the seam for that, not an implementation of it. No hot reload:
  values are read at boot, and a change needs a restart (the NIPS feed watcher and the TI feed loop remain
  the only hot-reloading things, each for its own reason). No secret *management* — a secret is still a
  file path or an env value, and this change only stops it being read back. No per-tenant configuration.
