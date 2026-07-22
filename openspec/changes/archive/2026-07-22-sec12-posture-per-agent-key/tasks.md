# Tasks — SEC-12 posture per-agent key
- [x] PostureSubscriber verifies against a PostureKeyResolver (subject -> enrolled key); subject binding.
- [x] splitSignedUpdate (parse envelope) so posture can pick the per-agent key before verifying.
- [x] LoadPostureRoster (<subject> <base64-pubkey> file) -> resolver; bad line/key/empty rejected.
- [x] Gateway wires OPENSHIELD_POSTURE_ROSTER (replaces the single POSTURE_PUBKEY). Risk unchanged.
- [x] Test: agent-A cannot forge agent-B's posture; own posture applied; unenrolled/unsigned rejected.
- [x] Mutation: disable the verify -> the agent-to-agent forgery passes.
- [x] make all clean; docs D157; sync; archive; commit; push; memory.
