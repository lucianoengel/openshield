# SEC-C · The access gate granted on no-match

## Why

`evalCandidate` returned `ACTION_ALLOW` with the reason *"no policy rule matched"*, unconditionally, for
every stage. The access proxy grants on `ALLOW`:

```go
if dec.GetAction() != corev1.Action_ACTION_ALLOW {
    http.Error(w, "access denied by policy", http.StatusForbidden)
    return
}
```

So **default-deny lived in the text of the operator's Rego, not in the engine.** Every access policy in
this repository — the integration fixtures, the tunnel tests, the documented example — ends with the
same line:

```rego
decision := {"action":"BLOCK","reason":"not authorized","confidence":0.9} if { not authorized }
```

That line is the entire security model of the gate, written as an ordinary-looking rule. Delete it,
shadow it with an earlier rule, or fail to extend it when a new input shape arrives, and the proxy
becomes default-**allow** in front of internal services. The diff shows one removed line, and a reviewer
has to *know* it was load-bearing.

The comment at the load site already asserted the property the code did not have:

> The access policy is identity-aware and DEFAULT-DENY (D87) — only the operator can author it. Load it,
> or abort: never fall back to the observe-first default (which is default-ALLOW and would admit
> everyone).

The fallback it refused was a whole *policy*. The no-match *outcome* of the policy it did load was the
same default-ALLOW, arrived at by a different route.

## What changes

1. **The no-match outcome belongs to the STAGE.** `policy.NewAccess` denies; `policy.New` and
   `NewComposite` continue to allow. This is not a detail of where to put a constant: the endpoint DLP
   pipeline must allow an unmatched event (they are the overwhelming majority — every ordinary file
   write on the host) and the access gate must deny one. Same engine, opposite correct answers, so the
   answer cannot be the engine's.

2. **An access policy is proven to deny an unknown principal at load.** A no-match default cannot catch
   a rule that is present and wrong — an unconditional allow, or a predicate that is vacuously true when
   the fields it reads are absent. `role != "banned"` reads like a denylist and admits every caller
   whose role could not be resolved. Such a policy *matches*, so no default fires. The probe evaluates
   the module against a canonical unknown principal and refuses to start if it is allowed.

3. **The probe's input is built by `buildInput`**, the same function that assembles a real request's
   document. A probe asserting against a shape the policy never sees passes for the wrong reason, and
   this input has gained fields (risk, posture, response intent, CASB) several times.

## Impact

- **Behaviour:** a correct access policy is unaffected — its authored decisions and reasons are
  unchanged. An incomplete one now denies where it previously admitted. A permissive one stops the
  gateway starting.
- **The observe pipeline is untouched**, and that is asserted by its own test, because the
  over-correction would be far more damaging than the bug: an engine-wide default-deny would block every
  ordinary file write on every endpoint, on the first deployment.
- **No schema, no proto, no migration.**
- **Deliberately not in scope:** the four-eyes-gated policy SAVE path (`CONSOLE-45`) is not built, so
  there is nothing yet to gate — `NewAccess` is the primitive it will need, and its
  `ErrAccessPolicyAdmitsUnknown` is the refusal a save must surface. Also out: warning on a policy that
  denies EVERYTHING (an outage, not a breach, and an operator finds out immediately).
