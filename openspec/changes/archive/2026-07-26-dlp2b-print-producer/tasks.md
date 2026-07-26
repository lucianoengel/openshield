## 1. Contract

- [x] 1.1 `EVENT_KIND_PRINT_JOB` + `PrintSubject{printer, job_user, byte_count, job_title_present}` — no
  document content, no title text (a title leaks the document name); regenerate; keep the bytes-field guard
  green with its allowlist unchanged.
- [x] 1.2 `exfil.ChannelPrint` + policy mapping by event kind; map the new kind to the `dlp` correlation
  domain (the D241 enum-completeness guard will fail until this is done).

## 2. The verdict path

- [x] 2.1 `internal/printguard`: fixed-shape framing (bounded, validated before allocation), a client for
  the filter and a server for the engine, request-id matched.
- [x] 2.2 Unit tests: round trip, every malformed frame class, oversized declared length.

## 3. The filter

- [x] 3.1 `cmd/openshield-print-filter`: parse the CUPS argv, read the job (stdin or file) up to the cap,
  ask the engine, then copy through byte-for-byte on allow or exit non-zero emitting nothing on deny.
- [x] 3.2 Tests: allow → output identical to input; deny → non-zero exit and NO output; unreachable engine →
  job passes through and the fail-open is reported. **Mutations:** emit output on deny → FAILs; abort on an
  unreachable engine → FAILs.

## 4. Engine side

- [x] 4.1 An env-gated print-verdict listener: classify the job content through the pipeline (sandboxed
  worker), emit the content-free event, and answer allow/deny.
- [x] 4.2 Test through the real engine: a job with a seeded CPF is denied and the serialized event carries
  none of the document text; a clean job is allowed.

## 5. Real CUPS proof (VM)

- [x] 5.1 On the VM: install the filter, define a virtual printer whose chain includes it, submit a job with
  `lp`, and assert a sensitive job is ABORTED while a clean job completes. Paste the output.

## 6. Gate and land

- [x] 6.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` + `make proto-check` + `check-agent-deps` green.
- [x] 6.2 Roadmap + decision register; document the install step and the chain-placement caveat.
- [x] 6.3 Commit with the `DLP-2b` handle, sync specs, archive.
