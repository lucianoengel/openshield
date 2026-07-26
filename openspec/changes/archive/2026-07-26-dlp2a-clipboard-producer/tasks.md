## 1. Contract

- [x] 1.1 `event.proto`: add `EVENT_KIND_CLIPBOARD_COPY` and
  `ClipboardSubject { uint32 byte_count = 1; string display_server = 2; }` as a new `target` oneof member;
  regenerate. No bytes field anywhere in it.
- [x] 1.2 Confirm `TestEventHasNoUnexpectedBytesFields` passes with the allowlist UNCHANGED — the mechanical
  proof the addition carries no content. Add a test that the clipboard subject has exactly the two expected
  fields, so a later "just add the text here" edit fails loudly.
- [x] 1.3 `internal/exfil`: add `ChannelClipboard` + its `String()`; extend the channel test.

## 2. The reader seam

- [x] 2.1 New `internal/clipboard`: `Reader` interface, `MaxBytes` cap, `Detect()` returning the display
  server (`wayland`/`x11`/none) from the environment, and `argv` builders for `wl-paste` and `xclip`.
- [x] 2.2 Linux backend: run the helper with a context timeout, read stdout capped at `MaxBytes` (truncate,
  do not read whole), resolve the binary with `LookPath` and report which one was found. A `!linux` stub
  returns a clear unsupported error, distinct from an empty clipboard.
- [x] 2.3 Unit tests: both argv builders; `Detect()` for wayland / x11 / neither; `MaxBytes` truncation
  (**mutation:** remove the cap → FAILs); the unsupported-platform error.

## 3. Change detection

- [x] 3.1 A `Watcher` that reads on a ticker, compares a SHA-256 of the content with the previous digest, and
  yields only on change. Document the digest as local-only dedup state, never emitted (D10/D11).
- [x] 3.2 Test with a scripted fake reader: same content 3 polls → 1 change; then new content → a second
  change; back to the first content → a third change (it tracks the LAST content, not a history).
  **Mutation:** ignore the digest → the repeat test FAILs.

## 4. Content plumbing

- [x] 4.1 A keyed content store: `Put(eventID, bytes)`, a `ContentResolver` that returns and DELETES the
  entry, a bound on entries, and CHAINING to a previously-installed resolver on a miss.
- [x] 4.2 Tests: resolve-once-then-released; the bound holds; **chaining** — a pre-existing resolver still
  answers its own events (**mutation:** overwrite instead of chain → FAILs).

## 5. The producer

- [x] 5.1 `cmd/openshield-engine`: `clipboardSource` — env-gated by `OPENSHIELD_CLIPBOARD_INTERVAL`, refuses
  to start (loudly, engine unaffected) when no display or no helper is found, and on each change registers
  the bytes in the store and emits the content-free Event with `byte_count` + `display_server`.
- [x] 5.2 `internal/policy`: map `EVENT_KIND_CLIPBOARD_COPY` to `ChannelClipboard` when building policy
  input — by KIND, not by path. Test that policy input for a clipboard event carries the clipboard channel.

## 6. The real-pipeline test (where the claim lives)

- [x] 6.1 Fake ONLY the `Reader`; run the real producer → real `engine.Process` (real worker, real policy)
  with clipboard text containing a seeded CPF. Assert: the classification reports the CPF detector; the
  **serialized Event bytes contain none of the seeded text**; `byte_count`/`display_server` are correct.
- [x] 6.2 **Mutation:** put the clipboard text into the Event → the no-content assertion FAILs.
  **Mutation:** drop the content registration → no detector hit → FAILs.

## 7. The real-display test (VM)

- [x] 7.1 A gated test (skips without a display): set a real X11 clipboard with `xclip -i` under `Xvfb`, read
  it back through the real X11 backend, and assert the round trip. Run it on the rooted VM (`Xvfb`, `xclip`
  and `wl-clipboard` are installed there) and paste the PASS into the decision record.
- [x] 7.2 State plainly in the record that this test cannot run on the dev workstation (no Xvfb) or in
  ordinary CI, so it strengthens rather than carries the claim.

## 8. Gate and land

- [x] 8.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green (the display test skips), plus `make proto-check`.
- [x] 8.2 Roadmap + decision register: DLP-2a done; record the polled/text-only/no-block limits, the
  engine-holds-bytes trade, and that DLP-2b (print) is next in the lane.
- [x] 8.3 Commit with the `DLP-2a` handle, sync the delta specs, archive the change.
