# Design — CONSOLE-8e

## Off the main path, and the test says so

D314's finding was that attestation on the agent's main path blocked it forever against a TPM that
accepts a connection and then does not answer — which is exactly what an un-started software TPM does. No
heartbeat, no telemetry, no posture, and no log line saying why, because every message came after the call
that hung.

So the engine starts attestation in a goroutine, and the integration test asserts the engine is still
observing afterwards. Without that assertion the scenario would pass on an endpoint that attests
beautifully and has stopped doing its job.

## Failures are logged and non-fatal

Attestation is a signal the gateway consumes, not a precondition for the agent existing. A device with a
broken TPM should still report heartbeats, posture and telemetry, and be visible as a device that CANNOT
attest — far more useful to an operator than a machine that has vanished.

TPM startup returning an error is INFO, not a warning: the overwhelmingly common case is a
firmware-started TPM answering "already started", and treating that as a failure would disable
attestation on every real machine to satisfy the emulator.

## Self-enrollment stays opt-in

A device asserting its own identity to the control plane is precisely what pre-auth tokens and EK
anchoring exist to constrain. Enabling it by default would hand that decision to a default.

## ParsePCRs takes a logger, and tolerates not having one

The warning about skipped entries is the D31 half of the function: `0,seven` yields `[0]`, a perfectly
valid non-empty baseline that no downstream check can flag as narrower than requested. A caller with no
logger must still not panic — a configuration typo turning into a dead agent would be a worse failure
than the one being reported.
