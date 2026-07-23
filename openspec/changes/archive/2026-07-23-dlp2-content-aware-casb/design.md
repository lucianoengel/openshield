## Context

`buildInput` (`internal/policy/mapping.go`) already derives content-free, metadata-only policy facts per
event kind: `event.exfil_channel` for a filesystem write (`exfil.Classify(path)`), `event.behavioral`
for a process exec (`behavioral.Analyze(...)`), and `event.host/method/path` for a network flow. The
worker's DLP classification lands in `st.Classification` (→ `input.classification` hits). CASB needs only
one new derivation: given a network flow's destination host + method, which cloud service is it, is it
sanctioned, and is it an upload — then the policy ANDs that with the existing content hits.

## Goals / Non-Goals

**Goals:**
- Classify a network flow's cloud service, sanctioned status, and upload-ness from metadata alone.
- Let a policy BLOCK sensitive content bound for an unsanctioned cloud upload, and allow it to a
  sanctioned one — preventive at the intercepting gateway (no root).
- Operator-configured catalog, hot-reloadable; inert when unconfigured (no pipeline change).

**Non-Goals:**
- Endpoint non-file producers (clipboard/print/screenshot — display/OS-gated).
- Path-level upload heuristics (multipart, `/upload`, resumable protocols), download/share operations,
  per-OAuth-app identity, shadow-IT discovery, mount-table resolution. All later DLP-2 increments.

## Decisions

1. **CASB is metadata enrichment, gateway-side — no worker, no proto.** Cloud-service classification is a
   pure function of host + method (+ path later), the same class of derivation as `exfil.Classify` and
   `behavioral.Analyze`. It therefore belongs in `buildInput`, added to the network `event` map as
   `event.cloud`. No content crosses, no IPC field, no `core.State` field, no proto change. This is the
   cheapest correct placement and mirrors an established pattern.

2. **Content is already present; CASB adds the destination and the policy ANDs them.** The killer rule is
   `sensitive_content AND unsanctioned_cloud_upload → BLOCK`. `input.classification` (worker DLP hits) is
   the content half; `event.cloud.{upload,sanctioned}` is the destination half. The engine computes
   neither verdict — the policy does (T1 closed-action-set discipline).

3. **Catalog shape.** `Catalog` holds services, each `{Name, Category, Sanctioned bool, hostSuffixes
   []string}`. `Classify(host, path, method)` matches `host` against the services' host-suffixes
   (component-aware suffix match, like the IOC domain match: `s3.amazonaws.com` matches a
   `amazonaws.com` suffix, `notamazonaws.com` does not), returns the first service matched, and sets
   `Upload = isMutating(method)` where mutating = POST/PUT/PATCH. A GET/HEAD to a cloud host is a
   recognized service but `Upload=false`, so a content+upload rule does not fire on a download. `path` is
   accepted now for a forward-compatible signature but unused in increment 1 (documented).

4. **Catalog file + hot-reload (mirrors the NIPS ruleset).** Block grammar:
   ```
   service dropbox category storage sanctioned
     host dropbox.com
     host dropboxusercontent.com
   service s3 category storage
     host s3.amazonaws.com
   ```
   A directive keyword takes the rest of the line; `#` comments; a malformed line (unknown directive,
   `host` outside a service, a service with no host, a bad category) is a load error — never a silent
   skip that would leave a service unrecognized while the operator believes it is covered. The watcher
   reads its baseline synchronously in the constructor (the async-baseline race), swaps a package-level
   `atomic.Pointer[Catalog]` via `casb.SetCatalog`, and serves-stale on a bad edit.

5. **Package-level active catalog, like `exfil.Default` but runtime-configured.** `buildInput` is a pure
   function of `st`; it reads the active catalog via `casb.Classify(...)`, which loads the atomic
   pointer. `nil` catalog → `nil` match → `event.cloud` omitted → existing pipelines unaffected. Startup
   sets it from `OPENSHIELD_CASB_CATALOG`; the watcher swaps it on change.

## Risks / Trade-offs

- **Host-suffix matching precision:** a too-broad suffix (e.g. `amazonaws.com`) would tag unrelated AWS
  traffic as "s3". Increment 1 uses the operator's catalog verbatim (their suffixes, their precision);
  the parser rejects a degenerately short suffix (like the NIPS URI min-length guard) so a typo cannot
  match everything. Finer path/API discrimination is a deferred refinement.
- **Upload = mutating-method is coarse:** a POST that is not a file upload (an API call) to a cloud host
  reads as an upload. Accepted for increment 1 — the policy still requires sensitive CONTENT to fire, so
  a contentless API POST does not trip the block. Path/multipart refinement is deferred and noted.
- **Inertness is load-bearing:** the whole feature must be a no-op when unconfigured (the default
  deployment). A test asserts a non-cloud host and an absent catalog both leave the pipeline unchanged.
- **SNI vs Host header:** the gateway exposes `ns.GetSniHost()`; for an intercepted HTTPS flow that is
  the destination. Matching on it is consistent with the existing IOC metadata match.
