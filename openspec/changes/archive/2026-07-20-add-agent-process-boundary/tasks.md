## 1. Record what shipped

- [x] 1.1 Write the `agent-process-boundary` spec covering the two-binary split, IPC framing,
      failure/truncation reporting and the hung-worker deadline
- [x] 1.2 Record `context_version` in the `decision-contract` spec (D27)
- [x] 1.3 Record the Context seam and the inert-data rule in `pipeline-dispatcher` (D28)

## 2. Verify the specs match the code

- [x] 2.1 Every requirement written here corresponds to an existing, mutation-verified test —
      no requirement describes an unproven property
- [x] 2.2 Confirm no code changes were needed: the code was correct, the specs were behind

## 3. Sync and archive

- [x] 3.1 Sync into `openspec/specs/`
- [x] 3.2 Archive with `--skip-specs`
