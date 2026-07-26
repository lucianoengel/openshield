package nips

// ParseInvocations exposes the parser-entry counter so a test can assert the VERIFY-BEFORE-PARSE
// ordering directly. Asserting only that a bad feed is refused cannot distinguish "verified first" from
// "parsed first and refused afterwards", and the ordering is the property that matters: the parser is
// the surface an attacker is trying to reach.
func ParseInvocations() uint64 { return parseInvocations.Load() }
