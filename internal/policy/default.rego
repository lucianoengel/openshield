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

# HIPS (Phase E, HIPS-5): a suspicious process-behavior score raises an alert. The score
# combines LOLBin use, suspicious parent→child lineage, and encoded/download-and-execute command
# lines (behavioral.Analyze, computed in buildInput). Observe-safe: the DEFAULT policy ALERTs, it
# does NOT KILL — an operator raises this to KILL_PROCESS deliberately (the closed action set is a
# security feature, T1). File and network events have no input.event.behavioral, so this is
# undefined for them and never fires.
behavioral_alert if {
	input.event.behavioral.score >= 0.5
}

# NIPS-2 (D300): a threat-intel match on the flow's destination. The engine matched an operator-supplied
# indicator — a domain, an IP, a CIDR or a URI substring — against this flow.
#
# It ALERTS, never blocks, for the same reason everything else here does (D1, observe-only by default):
# a public feed turning into automatic egress denial is how a poisoned or stale indicator becomes a
# self-inflicted outage. An operator raises this to BLOCK deliberately, which is what the closed action
# set is for.
#
# WITHOUT THIS RULE THE ENGINE WAS INERT. No shipped policy read `input.threat`, so a gateway logged
# "NIPS-2 threat-intel engine active", matched indicators, and did nothing with them — the feature
# existed everywhere except at the point where a match becomes a decision.
threat_match if {
	count(input.threat.matches) > 0
}

# A single alert flag composes the alert conditions, so the ALERT/ALLOW decision rules stay
# mutually exclusive (no conflicting `decision` value for one input).
alert if { alerting_hit }

alert if { behavioral_alert }

alert if { threat_match }

reason := "checksum-backed PII detected above the alert threshold" if { alerting_hit }

reason := "suspicious process behavior" if {
	behavioral_alert
	not alerting_hit
}

reason := "destination matched an operator threat-intel indicator" if {
	threat_match
	not alerting_hit
	not behavioral_alert
}

decision := d if {
	alert
	d := {"action": "ALERT", "reason": reason}
}

# No alert condition: an explicit, reasoned allow. Distinguishable in the ledger from
# "no rule matched" (which the Go layer handles when `decision` is undefined).
decision := d if {
	not alert
	d := {
		"action": "ALLOW",
		"reason": "no alert condition met",
	}
}
