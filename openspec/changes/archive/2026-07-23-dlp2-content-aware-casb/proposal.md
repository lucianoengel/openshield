## Why

DLP-2 is the flagship gap: *"a DLP that watches directories but not the channels users exfiltrate
through is not a DLP."* The file-channel foundation shipped (D194 tags a file write as
removable/cloud-sync/local), and `exfil-channel-awareness` names **content-aware CASB** as its
follow-up. This delivers it for the **network** plane: recognize when a flow is uploading to a cloud
storage/collab service, whether that service is operator-**sanctioned**, and combine that with the
content classification the worker already produces — so a policy can BLOCK sensitive data going to an
**unsanctioned** cloud sink while allowing the same to a sanctioned one. Because the gateway is an
intercepting proxy, a BLOCK here is genuinely **preventive** (no root).

## What Changes

- **New `internal/casb` package** — a `Catalog` mapping cloud **services** (Dropbox, Google Drive, S3,
  OneDrive/SharePoint, Box, Slack, …) to destination host-suffixes, each with a **category** and a
  **sanctioned** flag. `Classify(host, path, method) → *Match{Service, Category, Sanctioned, Upload}`,
  where `Upload` = a mutating method (POST/PUT/PATCH) to a known cloud host. A nil/empty catalog matches
  nothing (inert) — existing pipelines are unaffected.
- **Catalog file + hot-reload** — a block-grammar file (`service <name> category <cat> [sanctioned]`
  then its `host <suffix>` lines; `#` comments; a malformed entry is a load error, never a silent skip),
  with a watcher whose baseline is read synchronously in the constructor (the async-baseline race),
  swapping a package-level atomic catalog at runtime.
- **Policy input enrichment** — `buildInput` adds `event.cloud = {service, category, sanctioned,
  upload}` for a network event when `casb.Classify` returns a match — exactly like it already derives
  `event.exfil_channel` for a filesystem event and `event.behavioral` for a process event. **Pure,
  content-free metadata** (host/method), so it runs gateway-side: no worker, no proto/IPC, no
  `core.State` change.
- **Wiring** — the gateway/engine loads `OPENSHIELD_CASB_CATALOG` → `casb.SetCatalog` + starts the
  watcher, with a loud warn when unset (feature off), like the IOC-feed / NIPS-rules warns.
- A policy can now express the CASB rule: **sensitive content (`input.classification`) AND an
  unsanctioned cloud upload (`event.cloud`) → BLOCK**, sanctioned → allow/alert.

## Capabilities

### New Capabilities
<!-- none — this is the content-aware CASB follow-up the exfil-channel-awareness capability names -->

### Modified Capabilities
- `exfil-channel-awareness`: add **cloud-service (CASB) classification of a network flow** — the
  service, its category, whether it is sanctioned, and whether the flow is an upload — and expose it to
  the policy so a rule can gate sensitive content bound for an unsanctioned cloud sink. Complements the
  existing file-path channel classification with the network-upload channel.

## Impact

- **Code:** new `internal/casb/` (catalog + classifier + parser + reload watcher);
  `internal/policy/mapping.go` (`buildInput` adds `event.cloud`); gateway/engine startup loads the
  catalog. No worker change, no proto change, no migration, no new dependency.
- **Behavior:** with no catalog configured, nothing changes (inert). With one, a network event carries
  `event.cloud` and a CASB policy can prevent sensitive uploads to unsanctioned services at the gateway.
- **Deferred (later DLP-2 increments, stated honestly):** the non-file endpoint producers
  (clipboard/print/screenshot — display/OS-gated), path-level upload heuristics (multipart, `/upload`,
  resumable protocols), download/share operations, per-OAuth-app identity, shadow-IT **discovery**
  reporting, and runtime mount-table resolution for the file side.
