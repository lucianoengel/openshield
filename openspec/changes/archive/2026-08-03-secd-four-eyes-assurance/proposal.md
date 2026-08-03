# SEC-D · Four-eyes said nothing about the two defaults that cap it

## Why

The four-eyes control is well built. `approver <> requester` lives inside the UPDATE predicate, so two
operators racing cannot both succeed, and the comparison cannot be bypassed by a caller.

What it compares is an **identity string**, and two shipped defaults decide what an identity string is
worth:

- `OPENSHIELD_OPERATOR_ROLES_STRICT` defaults to `0`, so an identity with **no server-side record falls
  back to the role in its certificate**. Whoever obtains two operator certificates is both pairs of
  eyes, and neither identity has to exist in any table the deployment controls.
- `OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP` defaults to `0`, so an operator bearer token that is not
  sender-constrained is accepted. **Two stolen tokens are two operators.**

`docs/threat-model.md` already concedes that four-eyes is *"exactly as strong as the CA's issuance
discipline"*. Nothing in the control itself said so.

Both defaults are individually correct and were argued for on their own terms: turning either on before
a deployment has migrated locks every operator out, including the admin who would have to fix it. **The
defect is not the defaults.** It is that an approval recorded on such a deployment reads, forever, as
"alice requested, bob approved" — an audit trail attesting to a two-person control that may never have
existed. That is worse than not offering the control, because the trail is what an investigation later
relies on.

## What changes

1. **Every resolved approval records the assurance in force at that moment** — `strong` or `weak`.
   Recorded at resolution rather than derived at read time: a deployment that hardens next month must
   not retroactively make last month's approvals look strong, and one that loosens must not make them
   look weak.

2. **Every component offering four-eyes states what its own is worth at startup**, naming each switch
   that is off. A warning that says "identity is weak" without naming the knob is a warning that gets
   acknowledged and left alone. The confirmation prints when hardened too — a message that appears only
   on failure cannot be used to verify success.

3. **`OPENSHIELD_FOUR_EYES_REQUIRE_STRONG=1` refuses to GRANT an approval** the deployment cannot attest
   to, leaving the request pending. **Denials are never gated:** refusing to record a "no" would leave
   the dangerous request alive and approvable while blocking the operator trying to stop it, turning a
   hardening control into a way of keeping things pending.

4. **`AssessFourEyes` is the primitive a future four-eyes gate consults**, so "must refuse to enable
   unless both are hardened" is expressible rather than a note in a roadmap — `CONSOLE-45`'s policy save
   and `PLAT-5c`'s delivery are the two named consumers.

## Impact

- **Behaviour with the shipped defaults is unchanged** except that approvals now carry an assurance
  value and the binary says one more sentence at boot. Nothing that worked stops working.
- **One migration**, an additive column. Existing rows keep an empty assurance meaning "resolved before
  this was recorded" — deliberately not backfilled as `weak`, because the historical deployment's
  configuration is unknown and guessing it would put an unobserved claim in the audit trail.
- **Deliberately not in scope:** defaulting `REQUIRE_STRONG` on (it would break every existing four-eyes
  flow at the moment an operator is trying to approve something, which is worse than a recorded weak
  approval because it looks like the feature is broken); hardening the two underlying switches
  themselves, whose migration argument is unchanged; and requiring the two approvers to be different
  HUMANS rather than different identities, which no deployment-side signal can establish.
