# Design — posture subject↔key binding

## Verify against the claimed subject's key

The forgery works because one key verifies for every subject. Binding subject↔key removes it: to get
an update applied for subject S, the signature must verify against S's OWN enrolled key — i.e. the
signer must hold S's private key. An agent holds only its own private key, so it can sign its own
posture and no one else's. The check reads the subject from the (as-yet-unverified) envelope only to
SELECT the candidate key; the signature is then verified BEFORE the posture is applied, so
"verify-before-apply" holds — the same routing-then-verify the per-agent telemetry path uses.

## A resolver, roster-fed

`PostureSubscriber` now depends on a `PostureKeyResolver` (subject → key), not a single key. The
gateway builds one from a roster file (`LoadPostureRoster`), which is how the enrolled agent keys are
distributed to the gateway today; a resolver fed live from the control-plane roster is a follow-up.
Risk is unaffected — it is published by the control plane and correctly verifies against the single
control-plane key (the SEC-1 split: risk = one key, posture = per-agent keys).

## Mutation proof

The test enrolls two agents with distinct keys and has agent-A sign a compliant posture whose subject
is agent-B. It MUST be rejected. Disabling the signature verification lets that forgery through — the
"agent-A forged agent-B" assertion fails — proving the per-agent verify is the load-bearing guard.
