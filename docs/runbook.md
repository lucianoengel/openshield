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
<!-- b2-guidance -->

**Before enabling the file-open gate (B2)**, know what it costs. The inline decision classifies a
bounded prefix of every file opened in the watched directories, at roughly **0.4ms per KiB**:

| `OPENSHIELD_OPEN_PREFIX_BYTES` | cost per open | suits |
|---|---|---|
| 64 KiB (the ceiling) | ~26 ms | a quiet directory of sensitive documents — only ~5x margin against the window |
| 16 KiB (**default**) | ~6 ms | a shared working directory |
| 4 KiB | ~1.5 ms | anything busier |

The default is deliberately **not** the ceiling. At 64 KiB the margin against the permission window is
about five times, which sounds ample and is not: anything that slows the machine consumes it, and an
over-budget verdict does not arrive late — it **fails open silently** while the gate still reports
itself active.

Every open in those directories waits that long, and the waiting process is **uninterruptible**. Do not
point it at a source tree, a build directory, or anything on a hot path. Lowering the prefix trades
inline detection depth for latency — the async tier still classifies the whole file and contains it
afterwards, so what is lost is inline refusal of content that appears past the ceiling, not detection.

| `openshield-ztna-client` | endpoint (unprivileged) | Zero-Trust access broker for applications: presents the DEVICE certificate to the access proxy over the `HTTP_PROXY` convention, loopback-only. It brokers access — it does not prevent an application taking a direct route. |
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

### Back up, and drill the restore

```
OPENSHIELD_DSN=... ./scripts/backup.sh                       # pg_dump, custom format
OPENSHIELD_DSN=<scratch> OPENSHIELD_WITNESS_PUB=... \
  ./scripts/restore-drill.sh openshield-....dump             # restore, then PROVE it
```

**A backup you have never restored is not a backup.** The drill is the half that tells you whether those
files are evidence or bytes, and it does not report success until the ledger re-verifies.

Back up alongside the dump: each agent's forward-secure ledger state, and the **witness/anchor keys** — a
dump cannot be verified without the anchor it is checked against, so losing those keys turns every future
restore into an unprovable one.

*Limit:* the drill is destructive to the database it restores into. Point it at a scratch instance.

### Node / database recovery

| Lost | Recover by | What you cannot get back |
| --- | --- | --- |
| Control plane host | Reinstall, restore the dump, run the drill | Nothing, if the dump and anchors survived |
| Postgres only | Restore the dump into a new instance; re-point `OPENSHIELD_DSN` | Telemetry since the last dump |
| An agent host | Re-enrol it; a new identity is issued | That agent's local ledger — its entries are gone, and the gap is VISIBLE in the chain rather than silent |
| Witness/anchor keys | Nothing restores them | Completeness proof for everything anchored under them. Existing entries still hash-verify; they can no longer be proven un-truncated |

The last row is the one to plan around: the keys are the trust root, and no backup of the database
substitutes for them.

### Verify a restore

```
openshieldctl restore-verify --dsn <dsn> --anchor <anchor> --witness <witness-pub>
```

Exit `0` verified, `2` damaged (do not proceed), `1` undetermined (fix your monitoring first).

The witness key is **required**. Chain verification alone cannot detect truncation — a truncated ledger
hashes perfectly and simply stops early — and truncation is the most likely way a restore loses evidence.

*Limit:* completeness is proven only through the highest anchored sequence; the command reports how many
entries lie beyond it. Anchor cadence bounds this, not verification.

### Upgrade order: consumers before publishers

Every signed message carries a version, and **a consumer rejects a version it does not understand** rather
than partially applying it — the right direction for a containment or a fleet-wide disable, and the reason
order matters:

1. Endpoints and gateways (the consumers) **first**.
2. The control plane (the publisher) **second**.

Upgrading the control plane first is the failure mode: it publishes the new version to consumers that
reject it, and it looks like nothing is wrong from the publisher's side. Upgrading consumers first is
always safe — a newer consumer accepts the older version, because the accepted set is a RANGE and what a
build produces is a point inside it.

*Limit:* this ordering is a property of the wire contract, not something the software enforces across
hosts. Nothing stops an operator upgrading the control plane first; the consequence is rejected messages,
which are counted on each consumer.

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
