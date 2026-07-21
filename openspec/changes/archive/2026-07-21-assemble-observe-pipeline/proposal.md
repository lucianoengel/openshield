## Why

Audit finding #1, verified: **the product does not run — only its components,
driven by test code, do.** `cmd/openshield-engine/main.go` builds the whole
pipeline (signer, ledger, policy, worker, engine) then discards it (`eng := …;
_ = eng`) and idles on `ctx.Done()`; `cmd/openshield-agent` prints "pre-alpha,
not implemented" and exits. Every "runs end to end" claim — including recent
README wording — is proven by integration tests calling internal packages
directly, NEVER by a shipped binary. This is the sharpest instance of the
project's own recurring failure: a mechanism proven in isolation, false of the
assembled system. A deployer gets a binary that idles.

## What Changes

- `openshield-engine` actually RUNS the observe path. D52 established that
  fanotify NOTIFY mode works UNPRIVILEGED, so the engine opens the connector
  itself — no privileged agent needed for observe-only. It watches the configured
  directories (`OPENSHIELD_WATCH_DIRS`, comma-separated), loops
  `Next(ctx) → engine.Process(ctx, event)`, and records each Decision to the
  ledger. A classify failure is auditable, never a silent allow (D17).
- The privileged permission-mode agent (`cmd/openshield-agent`) is honestly
  labeled the DEFERRED inline-blocking component (D49), not a broken agent —
  observe-only needs only the engine.
- Proven at the BINARY level: a test builds the actual `openshield-engine` +
  `openshield-worker`, runs the engine against a temp watch dir with real
  Postgres, drops a file containing a valid CPF into the watched dir, and asserts
  an ALERT lands in the forward-secure ledger. This closes the gap that "end to
  end" was only ever tested via internal packages.
- README and CHANGELOG corrected to state precisely: the observe pipeline runs as
  the `openshield-engine` binary (unprivileged notify-mode fanotify); inline
  blocking / the privileged permission-mode agent is deferred (D49). No wording
  implies the full privileged path ships today.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `endpoint-engine`: the engine binary runs the assembled observe path (fanotify
  connector → classify → policy → decide → audit), proven as a running binary,
  not only as package tests.

## Impact

- Affected code: `cmd/openshield-engine/main.go` (wire the connector loop),
  `cmd/openshield-agent/main.go` (honest deferred-component message), a
  binary-level e2e test, README.md, CHANGELOG.md, docs (D62).
- Behaviour: the engine now does observe-only work (records Decisions); it still
  enforces nothing unless an enforcer is registered (D1/D14). D48's three-role
  split holds — the engine holds OPA+pgx, the worker is sandboxed, and observe
  mode simply does not need the privileged permission-mode agent.
- Honesty: the "runs end to end" claim becomes TRUE for the observe path as a
  binary, and the still-deferred inline path is stated as deferred, not shipped.
