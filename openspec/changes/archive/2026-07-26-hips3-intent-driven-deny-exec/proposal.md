## Why

**This change documents behaviour that already shipped** (D253, commit `fb6294c`). It exists because that
ticket was implemented without an OpenSpec change, so `inline-prevention` — the capability it modified —
never received a delta and today says nothing about response intents. The code, the tests and the decision
record are ahead of the spec, which is the drift this repairs.

The behaviour itself: the inline exec gate can now be driven by a signed `CONTAIN` Response-Intent, so
containment PREVENTS a contained entity's next execution rather than killing the process after it has run.

## What Changes

Nothing in the code. The spec gains what the code already does:

- An inline exec verdict **may** be driven by a coordinated-response intent delivered as typed policy
  **context** — and a policy that does not read it is **unaffected**.
- The intent reaches policy as a **closed enum value**, never free text.
- A containment is **liftable**: with the intent absent or expired, the same execution runs again.
- The gate's **fail-open** rule is unchanged.

## Capabilities

### Modified Capabilities

- `inline-prevention`: the inline exec decision can consume a coordinated-response intent as closed, typed
  policy context.

## Impact

- **Docs only.** No code, no tests, no migration — the implementation is at `fb6294c`.
- **Decisions:** documents **D253**; depends on **D14** (closed vocabulary), **D26** (the `ResolveContext`
  seam), **D17/D73** (fail-open), **SOAR-7/D252** (the signed intent).

### What this change does NOT claim or cover

- It adds no capability. If the delta and the code ever disagree, the code at `fb6294c` and its VM-proven
  test are the truth, and the spec is what is wrong.
- **Endpoint half only.** The gateway's enactment of the same intent is XDR-6/D254, documented separately.
- The kernel test exercises only the intent's **arrival**; signed publication is SOAR-7's and is tested
  there.
- Nothing here weakens fail-open: an operator who stops the engine gets unchecked execs, so containment
  depends on a live engine.
