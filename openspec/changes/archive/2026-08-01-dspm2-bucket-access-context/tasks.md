# Tasks

- [x] Probe the bucket's ACL, policy, block-public-access settings and default encryption, each
      independently allowed to fail
- [x] Resolve the exposure three-valued, with a proven exposure surviving an incomplete picture and a
      negative one not
- [x] Apply block-public-access neutering per source, only for the two settings that affect existing access
- [x] Carry the access context on the event contract (additive `ObjectAccess` on `ObjectSubject`)
- [x] Probe once per sweep and attach to every object discovered in it
- [x] State the access context in the sweep's coverage report
- [x] Wire `ObjectSubject` — bucket, key, store and exposure — into the policy input
- [x] Unit tests, including the refused-probe honesty case and the full block-public-access table
- [x] Integration scenario against a real S3-compatible store, with a benign-object negative control
