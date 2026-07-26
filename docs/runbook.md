# OpenShield operator runbook

What this is, what it costs to run, and what to do when it breaks. Every procedure here exercises
something that exists and is tested; where a procedure has a limit, the limit is stated next to it rather
than in a caveats section nobody reads.

## Deployment footprint

**What this is:** a single control plane, one Postgres, one NATS, and N endpoint agents. It is a
compose/systemd-shaped product. Several control-plane replicas may run for availability — exactly one is
leader at a time (ADR-3/PLAT-2b), and all singleton work (correlation, playbooks, threat-intel refresh,
ticket sync, retention) runs only there.

**What this is not:** a distributed cluster. There is no sharding, no multi-region coordination, and no
horizontal scaling of the control plane — a second replica is a standby, not extra capacity.

**Sizing: no load exercise has been run.** This section deliberately publishes no throughput or
endpoint-count figures, because measuring them is work this project has not done, and an unmeasured number
in a runbook is read as a commitment.

## Components

| Binary | Runs where | Purpose |
| --- | --- | --- |
| `openshield-server` | control plane | Ingests telemetry, correlates incidents, runs playbooks, serves the operator API. |
| `openshield-gateway` | network path | Inline network decisions (NIPS, DNS sinkhole, ZTNA broker). |
| `openshield-agent` | endpoint (privileged) | Kernel-facing producers. Never parses untrusted bytes (D13). |
| `openshield-engine` | endpoint (unprivileged) | The pipeline: classify, decide, enforce, audit. |
| `openshield-worker` | endpoint (sandboxed) | Content parsing, isolated from the privileged agent. |
| `openshield-fleet-agent` | endpoint | Publishes telemetry to the control plane. |
| `openshieldctl` | operator workstation | Verify the ledger, verify a restore, verify a release, read timelines. |
| `openshield-anchor` | operator/witness | Exports and witnesses external anchors. |
| `openshield-provision` | operator | Enrollment and provisioning. |
| `openshield-print-filter` | endpoint (CUPS) | Print DLP; sits in the CUPS filter chain. |
| `openshield-fim-baseline` | endpoint/operator | Builds the file-integrity baseline. |
| `openshield-dlp-index` | operator | Builds the signed exact-data-match index. |

This table is checked against `cmd/` by test, in both directions.

## Procedures

### Verify a release before installing it

```
make verify-release DIST=<dir>          # or: openshieldctl verify-release --dir <dir>
```

Checks every artifact's digest against the signed manifest, the manifest against the release public key,
and reports any file present that the manifest does not name.

*Limit:* a signature proves origin, not correctness. A stolen signing key signs anything — what bounds
that is reproducibility: rebuild the commit and compare digests.

### Stop enforcing, now

**One host, control plane unreachable:**
```
touch /etc/openshield/EMERGENCY_DISABLE     # optionally write the reason into it
```

**Fleet-wide:** set the enforcement-disable configuration setting; it propagates within one config poll
interval.

Enforcement stops; **detection, decisions and the audit trail continue** — the record of what would have
been enforced is what you will need afterwards. Every suppression is counted with the reason.

*Limit:* the fleet path reaches components that read the configuration store. **Endpoint agents do not** —
they are disabled by their local file until the signed-channel path ships.

*Reversal:* remove the file, or unset the setting. The switch must be affirmatively engaged; an unreadable
source never disables enforcement.

### Verify a restore

```
openshieldctl restore-verify --dsn <dsn> --anchor <anchor> --witness <witness-pub>
```

Exit `0` verified, `2` damaged (do not proceed), `1` undetermined (fix your monitoring first).

The witness key is **required**. Chain verification alone cannot detect truncation — a truncated ledger
hashes perfectly and simply stops early — and truncation is the most likely way a restore loses evidence.

*Limit:* completeness is proven only through the highest anchored sequence; the command reports how many
entries lie beyond it. Anchor cadence bounds this, not verification.

### After a rollback: check schema skew

`openshield_schema_skew` (and a startup warning) reports how many migrations the database has that this
binary does not. Non-zero means this process is reading a schema ahead of it. It starts anyway — refusing
would turn a rollback into an outage.

*Limit:* **migrations are forward-only.** Rolling the **binary** back is supported; rolling the **schema**
back is not.

### Change configuration

Bootstrap settings (DSN, listen addresses, TLS material, credential locations) come from the environment
or a file and need a restart. Everything else is stored in the database, changed as an attributed revision,
validated at save, and applied to running processes within one poll interval.

```
openshield-server config        # effective values with each one's origin; secrets shown as set/unset
```

*Limit:* a dynamic setting placed in the environment does **not** take effect and is reported as ignored.
Override one deliberately with `OPENSHIELD_BREAKGLASS=<KEY>`; it then applies **and** is reported as an
override. Secrets are never stored in the database — set them on the host.

## Failure modes

| Symptom | Likely cause | First check |
| --- | --- | --- |
| No incidents raised | Correlation interval is 0, or the leader is not elected | `openshield-server config`; leader logs |
| Nothing paged | No sink configured, or a routing rule matched nothing | `openshield_notify_unrouted_total` |
| Enforcement not happening | Emergency disable engaged | The break-glass file; suppression counters |
| Agent silent | Overdue threshold exceeded | `/overdue`; heartbeat metrics |
| Telemetry rejected | Unenrolled, revoked, or a replayed sequence | `openshield_rejected_telemetry_total` |
| Threat intel stale | Feed refused (bad signature) — previous snapshot kept | Server log; `ioc_feeds.ingested_at` |
| Config change not applying | It is a bootstrap field, or ignored as an env override | `openshield-server config` origins |
