// Package enforcers holds enforcement plugins.
//
// An Enforcer receives ONLY a Decision. It never learns which classifier matched,
// which pattern fired, or how confidence was computed (the CrowdSec separation).
//
// The action set is CLOSED and TYPED — Block, Alert, Quarantine-local,
// Encrypt-local (docs/decisions.md D14). It is deliberately not an open framework:
// an open action surface would let a compromised control plane express "upload this
// file to a URL", indistinguishable from the platform's own telemetry. The closed
// set is what makes "the server coordinates, it does not control" architectural
// rather than aspirational.
//
// Phase 1 is observe-only (D1): Decisions are recorded, not enforced.
package enforcers
