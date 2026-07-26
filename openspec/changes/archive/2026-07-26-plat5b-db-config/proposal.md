## Why

PLAT-5 (D262) typed the configuration and derived a schema from it — but left env and a file as the only
sources, which is the *Splunk* model: layered files, precedence that needs a tool to reason about, and
"what is this cluster actually running?" answerable only by logging into hosts. That is not what a platform
is expected to look like, and it does not survive contact with a UI.

Serious platforms split configuration in two and are explicit about it. Elastic states it as *static*
(`elasticsearch.yml`, deliberately near-empty) versus *dynamic* (cluster state, changed through the API).
CrowdStrike goes further — the sensor takes an install identity and nothing else; every policy is a cloud
object. Network platforms add the piece enterprises actually ask for: a candidate → commit → **revision**
model, so a change has an author, a diff and a rollback.

## What Changes

- **Every field declares a SCOPE.** `bootstrap` — what the process needs to start and reach the database
  (DSN, listen addresses, TLS material, the config file itself): env/file only, restart to change,
  deliberately tiny. `dynamic` — everything else: **the database is the only source**, applied
  cluster-wide, changed without touching a host.
- **No env override of a dynamic setting.** This is the trap the previous increment proposed and this one
  refuses: a setting the UI shows as X while a host runs Y, silently, is what makes fleet configuration
  unanswerable. A documented break-glass exists and is **reported as an override**, never applied quietly.
- **Revisions, not writes.** A change is a revision with an author, a note, a timestamp and a per-key
  diff. That gives audit ("who widened the retention window"), and rollback to any prior revision.
- **Live apply.** A watcher swaps the settings snapshot when the revision changes, and the loops read
  their parameters per tick instead of capturing them at start. Without this it is a config file with
  extra steps.
- **Secrets never enter the config store.** A `KindSecret` field is refused by the write path outright;
  its value stays in env or a file on the host. A backup of the config database therefore contains no
  credentials.
- **Validation on save, not at next boot**, reusing the same field declarations — so a bad value is
  refused when the operator types it.

## Capabilities

### Modified Capabilities
- `typed-config`: adds field scope, a database-authoritative dynamic tier, revisions with audit and
  rollback, live apply, and the rule that secrets are never stored.

## Impact

- **New code**: `internal/config` gains `Scope`, `DBSource`, `Watcher`; `internal/controlplane/settings.go`
  (revisions, apply, rollback); `retain.DynamicLoop`.
- **Migration 036**: `config_settings`, `config_revisions`, `config_changes`. Additive.
- **BREAKING for one behaviour, deliberately**: a dynamic field set in the environment no longer takes
  effect — it is reported as an ignored override at boot. Bootstrap fields are unaffected.
- **Honest scope**: no UI (PLAT-1) — this is the model and the API it will call. No per-node scoping of
  dynamic settings: they are cluster-wide, and a genuinely per-node value belongs in bootstrap. No
  scheduled/staged rollout of a revision. No secret management or keystore — only the rule that secrets
  stay out. The server binary only; gateway and agent remain a follow-up.
