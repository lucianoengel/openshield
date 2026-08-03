# Tasks — SEC-C access default-deny

- [x] 1. `Stage.noMatch`, zero value ALLOW so every existing constructor is unchanged.
- [x] 2. `evalCandidate` takes the stage's no-match outcome; `noMatchReason` distinguishes the two.
- [x] 3. `policy.NewAccess` — no-match BLOCK plus the load-time probe.
- [x] 4. `denyUnknownPrincipal` over two canonical principals (nil and zero context), built through
      `buildInput`; `ErrAccessPolicyAdmitsUnknown` so a caller can identify the refusal.
- [x] 5. Gateway access mode loads via `NewAccess`.
- [x] 6. Unit tests: the deleted-deny-line policy still denies and still serves the authorized role; a
      correct policy is unaffected and keeps its authored reason; the observe pipeline still allows;
      both permissive shapes are refused at load; both correct shapes still load.
- [x] 7. Mutation-verify all five.
- [x] 8. Integration: an incomplete policy denies through the real binary; a permissive one stops it
      starting. Both fail when the wiring is mutated back to `policy.New`.
- [x] 9. Spec delta (MODIFIED the no-match requirement, ADDED the probe) + roadmap.
