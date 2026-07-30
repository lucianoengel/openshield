# The offline queue's recovery half was never tested, and testing it found a silent fleet outage

## Why

`TestTelemetryIsSpooledDuringAnOutage` stops the broker and asserts the spool directory becomes
non-empty. That is half of D40/D67, whose claim is "spool signed telemetry when the control plane is
unreachable and **re-send it on reconnect**, so an outage causes a gap, not silent loss".

**No scenario ever brought a broker back.** So `Queue.Drain`, `SignedPublisher.Flush` and the NATS
reconnect both depend on ran in no end-to-end test. The half that was asserted is the half that costs
nothing if it is wrong — a spool that fills and never empties looks identical to a working one until an
investigator asks about the outage window.

This came out of the enterprise gap assessment, which named **offline-queue drain after a real
disconnection** as one of four distributed properties the single-host fleet topology cannot prove.

## What changes

- `Stack.RestoreBroker` / `Stack.RestoreBrokerEmpty` — a broker can now come back, with its JetStream
  state or without it. `StopBroker` stops a `--rm` container so podman removes it; the restore starts a
  new one **rebinding the same host port**, because an agent's `OPENSHIELD_NATS_URL` is fixed at startup
  and a broker on a different port is not the same broker to it. The JetStream store moved into a named
  volume so a restart is a restart.
- `TestASpooledOutageDrainsWhenTheBrokerReturns` — the recovery half, asserted on the spool becoming
  EMPTY. Mutation-verified: disabling `Flush` fails it on the drain (138s), and the restored version
  passes in 19s.

## Impact

- No production behaviour change. Test and harness only.
- Affected capability: **offline-queue** — gains the drain requirement and the restart-versus-replacement
  distinction.

## What this FOUND, and is deliberately not fixing here

A broker that returns with **empty** JetStream state wedges the fleet permanently and **silently**.
Reproduced: rows frozen for 30s+ while the agent published every 500ms, and the control plane logged
nothing. A volume-backed restart of the same broker recovers fully (2 → 120 rows), which is what makes
this a specific defect rather than a general outage story.

`natsx.EnsureTelemetryStream` is called from `controlplane.Run` and `SignedPublisher.UseJetStream`, both
at **process startup only**, so nothing recreates a missing stream. This is ordinary ops — `podman rm`
and recreate the broker, or an orchestrator moving it onto new storage.

**It is not fixed here because a half-fix is worse than none.** Re-ensuring the stream from the agent on
reconnect would recreate it while the control plane's durable consumer — deleted along with the stream —
stays dead. Publishes would then succeed, the stream would exist, and still no row would appear: harder
to diagnose than the current failure, and it would look fixed. The fix needs a control-plane reconnect
handler that re-ensures and **re-subscribes**, which is a lifecycle change in the ingest path and
deserves its own change. Filed as **PLAT-10** with the reproduction, and the minimum bar recorded there:
even if self-healing is deferred, the server must say something, because a silent fleet-wide telemetry
outage is a direct D31 violation.

## Honest limits

- The outage here is a **broker** outage, not a network partition of the endpoint. A true partition —
  the agent's interface removed, and a different IP on rejoin — is the container-topology increment;
  the podman primitives for it are verified (rootless `network disconnect`/`connect` works, a static
  agent runs in an alpine container, `host.containers.internal` is reachable) but the test is not written.
- The reconnect window is short by construction here. The NATS client's defaults are
  `MaxReconnects=60` × `ReconnectWait=2s`, and the agent passes **no** reconnect options — so an endpoint
  offline for more than roughly two minutes gives up permanently and its spool never drains. This
  scenario does not cross that boundary and therefore does not prove or disprove it. Named as the next
  thing to measure rather than assumed either way.
