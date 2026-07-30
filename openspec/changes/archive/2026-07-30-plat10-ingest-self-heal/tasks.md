# Tasks

- [x] `Server.healIngest` — poll the durable consumer, announce, recreate the stream, resubscribe.
- [x] Keep the repair narrow: only a missing consumer/stream, never any error.
- [x] Extract `subscribeSignedDurable` so the repair cannot drift from the startup path.
- [x] Move `sigSub` into its own field; unsubscribe it in `Close`.
- [x] Count repairs AND repair failures separately.
- [x] `TestABrokerThatComesBackEmptyDoesNotWedgeTheFleet`.
- [x] Mutation-verify: no healing must fail the scenario (and confirm the mutant COMPILED — vet is not build).
- [x] Confirm the control-plane package and the other outage scenarios still pass.
- [x] `docs/unwired-audit.md` — Round 50; roadmap: PLAT-10 done.
- [x] `make quick` green.
