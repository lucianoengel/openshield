## ADDED Requirements

### Requirement: An endpoint whose OWN network vanishes must recover, not just one whose broker stops

Verification SHALL include a scenario in which the AGENT is partitioned — its network interface removed and
later restored on a different address — as distinct from a scenario in which the broker is stopped.

The two are not interchangeable, and a client that handles the second need not handle the first. A stopped
broker sends a RST and the client knows at once. An endpoint whose interface disappears is left holding a
TCP connection that is dead and looks open: nothing arrives to invalidate it, so until a keepalive times out
the client still reports connected, does not reconnect, and every attempt to drain the spool fails while the
spool keeps growing. DNS goes with the interface, so the broker's name stops resolving. On rejoin the
endpoint has a different address.

This is also the outage endpoints actually experience most: a closed laptop, a dropped VPN, a radio switched
off.

#### Scenario: A partitioned agent recovers when its network returns
- **WHEN** an agent's network interface is removed while it keeps producing, and later restored on a
  different address
- **THEN** the records held during the partition are delivered and stored

#### Scenario: A dead-but-open connection is detected in seconds, not minutes
- **WHEN** the connection is silently dead because the interface went away
- **THEN** the client notices within tens of seconds and begins reconnecting, rather than waiting out a
  multi-minute keepalive budget during which it neither delivers nor recovers

#### Scenario: A keepalive budget long enough to strand the spool is caught
- **WHEN** the keepalive interval is left at a multi-minute default
- **THEN** the scenario fails because the spool does not drain after the network returns
