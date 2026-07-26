## 1. Exclusions before capture (the privacy defect, first)

- [x] 1.1 `internal/clipboard`: an `Exclusions` set with password managers by default (keepassxc, bitwarden,
  1password, gnome-keyring, pass, seahorse, …) plus an operator-extensible list; matched on the SOURCE
  application's executable path/basename.
- [x] 1.2 The check runs BEFORE the content is read. Test: an excluded source's copy is never read (assert
  the reader is never called), no event is produced. **Mutation:** filter after reading → FAILs.

## 2. The X11 client

- [x] 2.1 Add `github.com/jezek/xgb`; confirm `check-agent-deps.sh` still passes (the privileged agent must
  not gain it) and that cross-compilation is unaffected.
- [x] 2.2 `internal/clipboard/x11` (build-tagged linux): connect, query XFIXES, select
  `SelectionOwnerNotify` on CLIPBOARD, and resolve a window to a PID via `_NET_WM_PID` → `/proc/<pid>/exe`.
- [x] 2.3 Unit-test the pure parts without a display: atom/target selection, the window→PID→path resolver
  against a synthetic property table, and capability reporting.

## 3. Capture, event-driven and attributed

- [x] 3.1 On `SelectionOwnerNotify`: resolve the SOURCE app, apply exclusions, then convert the selection
  (UTF8_STRING, falling back to STRING) with the existing `MaxBytes` cap.
- [x] 3.2 Emit the content-free event as today, now carrying the source application, and register the bytes
  for classification exactly as increment 1 does.

## 4. Mediation and per-destination enforcement

- [x] 4.1 Take CLIPBOARD ownership when a captured copy is classified sensitive (leave a non-sensitive copy
  alone entirely — ownership churn is visible to other clients).
- [x] 4.2 Answer `SelectionRequest`: support TARGETS; resolve the REQUESTOR window to the destination app;
  ask the injected decision callback with (classification, source, destination); serve the content on allow,
  and refuse (empty `SelectionNotify` property) on deny.
- [x] 4.3 Refuse transfers beyond the cap rather than implementing INCR, and say so in the audit reason.
- [x] 4.4 Relinquish ownership on stop/failure so the clipboard keeps working (D17). Test: after the
  mediator stops, a normal copy/paste round trip still succeeds. **Mutation:** keep ownership after stop →
  paste returns nothing → FAILs.

## 5. The real-X11 proof (VM, Xvfb)

- [x] 5.1 Gated end-to-end on the VM: `Xvfb` + a real `xclip -i` copy captured event-driven; then a real
  `xclip -o` paste from a SEPARATE process, ALLOWED by the decision callback → content served; and a second
  run DENIED → the paster receives nothing.
- [x] 5.2 Assert destination attribution: the decision callback saw the requesting process's executable.
  **Mutation:** ignore the decision and always serve → the deny case FAILs.
- [x] 5.3 Paste the PASS output into the decision record; state that it requires Xvfb and therefore does not
  run on the dev workstation or in ordinary CI.

## 6. Honest capability reporting

- [x] 6.1 A `Capabilities{Capture, SourceAttribution, DestinationAttribution, Enforcement}` report per
  backend: X11 full; Wayland capture+enforcement only, destination attribution UNAVAILABLE by protocol.
- [x] 6.2 The engine logs exactly what it obtained at startup. Test the Wayland reporter claims no
  destination attribution. **Mutation:** report destination attribution on Wayland → FAILs.

## 7. Wire, gate, land

- [x] 7.1 `cmd/openshield-engine`: mediation opt-in; the decision callback runs the pipeline for the
  destination; with mediation off, D246's behavior is unchanged.
- [x] 7.2 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` + `make proto-check` + `check-agent-deps` green; VM test
  run and pasted.
- [x] 7.3 Roadmap + decision register: record the dependency departure, the Wayland protocol limit, the
  clipboard-manager competition, and what remains unlike Windows DLP (no injection, no RDP channels).
- [x] 7.4 Commit with the `DLP-2a` handle, sync the delta spec, archive the change.
