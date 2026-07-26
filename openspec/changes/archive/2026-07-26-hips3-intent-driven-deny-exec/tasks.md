## 1. Verify the shipped code satisfies each requirement

- [x] 1.1 Intent as typed context: `core.Context.ResponseIntent`/`HasResponseIntent` (closed enum, not
  text) and the policy projection `response_intent`/`has_response_intent` in `internal/policy/mapping.go`.
- [x] 1.2 Resolution via the existing seam: `engine.SetIntentResolver` installing `ResolveContext`.
- [x] 1.3 Inline refusal, liftability and the unchanged fail-open: the VM-gated kernel test
  `TestKernelExecDeniedByContainIntent` (no intent → runs; CONTAIN → EPERM; lifted → runs) and the
  fail-open tests in `internal/agent/execipc`.
- [x] 1.4 Neutral consumer package: `internal/intent` imported by both sides, with no endpoint→gateway
  dependency.

## 2. Land the delta

- [x] 2.1 `openspec validate`; sync the `inline-prevention` delta into the capability spec; archive.
- [x] 2.2 Commit noting this is retroactive documentation of D253, not new behaviour.
