package gateway

import "time"

// SetVerifierClock injects a clock into an AttestationVerifier for tests
// (attestation freshness / TTL is time-dependent, R34-1).
func SetVerifierClock(v *AttestationVerifier, now func() time.Time) { v.setClock(now) }
