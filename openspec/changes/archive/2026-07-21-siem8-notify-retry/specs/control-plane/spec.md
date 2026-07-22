# control-plane (delta)

## MODIFIED Requirements

### Requirement: Alerts are delivered to a configured sink, best-effort
The control plane MUST be able to deliver alerts to a configured notification sink (a webhook) in
addition to recording them, so a human is told rather than having to poll. A peer-UEBA alert MUST
trigger a notification when it is recorded. Delivery MUST be best-effort: a sink error is logged and
counted, never propagated — a down sink MUST NOT break telemetry ingest or the detection.

Delivery MUST retry a TRANSIENT failure (a 5xx, a 429, a timeout, a refused connection) with
bounded backoff before giving up, so a momentary blip does not silently drop the notification, and
MUST NOT retry a PERMANENT failure (a 4xx client error, a notification that will not serialize),
since retrying cannot fix it. The retry MUST be bounded (a fixed maximum number of attempts) and
MUST stop promptly when its context is cancelled.

#### Scenario: A webhook receives an alert as JSON
- **WHEN** a notification is delivered to a configured webhook
- **THEN** the sink receives the notification as JSON with its kind and fields

#### Scenario: A transient failure is retried and a permanent one is not
- **WHEN** a sink returns a transient error (5xx) and then a permanent error (4xx) on later notifications
- **THEN** the transient delivery is retried up to the attempt budget while the permanent one is attempted once, and in both cases the final failure is logged rather than breaking ingest

#### Scenario: A failed delivery does not break ingest
- **WHEN** the sink returns an error
- **THEN** the recorded alert stands and telemetry processing continues

