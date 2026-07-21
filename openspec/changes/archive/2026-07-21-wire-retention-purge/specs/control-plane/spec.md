# control-plane delta

## ADDED Requirements

### Requirement: The fleet aggregate has an enforced retention window
The control plane MUST purge the fleet aggregate (received telemetry and derived peer alerts) older
than a configurable window, on a periodic timer. Because the fleet aggregate is a derived detection
view and not the evidentiary ledger, its purge is a hard delete; the number of rows removed is logged.

#### Scenario: Aggregate rows past the window are deleted, recent rows kept
- **WHEN** the fleet-aggregate purge runs with a cutoff
- **THEN** telemetry and peer-alert rows older than the cutoff are deleted and rows newer than it remain
