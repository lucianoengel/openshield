# network-gateway delta

## ADDED Requirements

### Requirement: The gateway classifies concurrent flows across a worker pool
The gateway MUST be able to classify concurrent flows in parallel by using a pool of workers rather
than serializing every body through a single worker. The pool MUST be a drop-in for the single worker
(the same classify interface), so the gateway pipeline is unchanged.

#### Scenario: The gateway uses a worker pool sized by configuration
- **WHEN** the gateway binary is configured with a worker-pool size
- **THEN** it starts that many workers and classifies flows across them, bounded by the pool size
