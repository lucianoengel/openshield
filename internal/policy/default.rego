# OpenShield default Phase-1 policy.
#
# Observe-only (D1): this policy emits ALERT or ALLOW, never BLOCK. The engine
# CAN express BLOCK — the action set is complete — but enforcement is Phase 2,
# so the shipped default never selects it.
#
# It is a pure function of its input. The engine is loaded with no clock, no
# randomness and no network (see policy.go), so this evaluates deterministically.
package openshield

import rego.v1

# Alert when a checksum-backed detector (CPF or credit card) is present above a
# confidence threshold. These have real validators, so a hit is strong evidence;
# SSN and email are weaker and do not trip an alert on their own here.
strong_detectors := {"DETECTOR_TYPE_CPF", "DETECTOR_TYPE_CREDIT_CARD"}

alerting_hit if {
	some h in input.classification
	h.type in strong_detectors
	h.confidence >= 0.85
}

decision := d if {
	alerting_hit
	d := {
		"action": "ALERT",
		"reason": "checksum-backed PII detected above the alert threshold",
	}
}

# No strong hit: an explicit, reasoned allow. Distinguishable in the ledger from
# "no rule matched" (which the Go layer handles when `decision` is undefined).
decision := d if {
	not alerting_hit
	d := {
		"action": "ALLOW",
		"reason": "no checksum-backed PII above threshold",
	}
}
