## ADDED Requirements

### Requirement: A long-lived process MUST retry its broker connection forever

Every long-lived OpenShield process SHALL reconnect to the broker without a retry ceiling, with jitter,
and SHALL report losing and regaining the connection.

nats.go defaults to 60 attempts at 2s — a budget of roughly two minutes, after which the client closes
permanently and the process never publishes or receives again while continuing to run. No process passed
any reconnect option, so all of them inherited it. Two minutes is not a long outage: a laptop closed over
lunch, a switch reboot, a VPN drop, a broker upgrade.

The consequence differs by process and none of them is acceptable:

- The AGENT keeps producing into the durable spool that exists so an outage causes a gap rather than
  silent loss, and can now never drain it — so the spool fills to its ceiling and begins DROPPING THE
  OLDEST records. A bounded outage silently becomes unbounded evidence loss.
- The CONTROL PLANE stops consuming, which is the whole fleet's ingest rather than one endpoint.
- The ENGINE and GATEWAY stop publishing decisions, so enforcement continues and the record of it does not.

Jitter is required, not cosmetic: a fleet waiting on one fixed interval reconnects in lockstep and
stampedes the broker that just came back.

A SHORT-LIVED command MUST NOT use this policy. An operator subcommand that publishes one message and
exits should fail promptly; retrying forever would hang a CLI.

#### Scenario: An outage longer than the default retry budget still recovers
- **WHEN** the broker is unavailable for longer than the client's default reconnect budget and then returns
- **THEN** the process reconnects and the records held during the outage are delivered and stored

#### Scenario: A retry ceiling is caught
- **WHEN** a finite reconnect ceiling is configured
- **THEN** the scenario fails because the spool never drains

#### Scenario: Losing the broker is reported when it happens
- **WHEN** the broker connection drops
- **THEN** the process says so, rather than leaving it to be inferred from missing data later

#### Scenario: A clean shutdown raises no alarm
- **WHEN** a process closes its broker connection deliberately during shutdown
- **THEN** no permanent-failure warning is emitted, because a maximum-severity line on every normal exit
  is one operators learn to ignore
