# control-plane (delta)

## MODIFIED Requirements

### Requirement: Alerts are delivered to a configured sink, best-effort
The control plane MUST be able to deliver alerts to a configured notification sink (a webhook) in
addition to recording them, so a human is told rather than having to poll. A peer-UEBA alert MUST
trigger a notification when it is recorded. Delivery MUST be best-effort: a sink error is logged and
counted, never propagated — a down sink MUST NOT break telemetry ingest or the detection.

Delivery MUST run OFF the ingest path — a slow or retrying sink MUST NOT stall telemetry ingest; the
control plane queues the notification and delivers it asynchronously, dropping and counting a
notification only when the delivery queue is saturated. Delivery MUST retry a TRANSIENT failure (a
5xx, a 429, a timeout, a refused connection) with bounded backoff before giving up, and MUST NOT
retry a PERMANENT failure (a 4xx client error, a notification that will not serialize). Each
notification MUST carry a stable idempotency key so a receiver can dedupe a retried delivery.

#### Scenario: A webhook receives an alert as JSON
- **WHEN** a notification is delivered to a configured webhook
- **THEN** the sink receives the notification as JSON with its kind, fields, and idempotency id

#### Scenario: A slow sink does not stall ingest
- **WHEN** the configured sink blocks or retries during delivery
- **THEN** the alert is queued and ingest proceeds without waiting on delivery, and a saturated delivery queue drops and counts a notification rather than blocking

#### Scenario: A transient failure is retried and a permanent one is not
- **WHEN** a sink returns a transient error (5xx) and then a permanent error (4xx) on later notifications
- **THEN** the transient delivery is retried up to the attempt budget while the permanent one is attempted once, and in both cases the final failure is logged rather than breaking ingest

#### Scenario: A failed delivery does not break ingest
- **WHEN** a configured sink is unreachable
- **THEN** the alert is still recorded, the delivery failure is counted, and ingest is unaffected
