# Tasks

- [x] `internal/connectors/objectstore`: SigV4 signing (stdlib HMAC-SHA256), ListObjectsV2 + ranged GET.
- [x] Bounded sweep: objects per sweep, bytes per object, concurrent fetches — and REPORT what was skipped.
- [x] Producer seam: `Next(ctx) (*corev1.Event, error)`, matching `filewatch.Watcher`.
- [x] `EVENT_KIND_OBJECT_DISCOVERED` in the proto, regenerate, `make proto-check` clean.
- [x] Try `FilesystemSubject.resolved_path` for `s3://bucket/key`; RECORD the fitness verdict either way.
- [x] Wire into `cmd/openshield-engine`, off by default, content via the ContentStore BEFORE the send.
- [x] Unit tests: SigV4 against known-answer vectors; pagination; the skipped-count report.
- [x] Integration test against real MinIO in podman: within-ceiling detected, past-ceiling NOT, no content
  on the Event.
- [x] Mutation: removing the ceiling report, and the store-before-send ordering, must each fail a test.
- [x] Docs: capability spec, roadmap DSPM-1 status, and the fitness verdict next to T-004's.
- [x] `make quick` green; targeted package + integration tests only.
