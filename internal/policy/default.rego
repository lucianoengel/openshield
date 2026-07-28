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

# NIPS-3: a DNS query whose name looks like a covert channel — long, high-entropy subdomain labels
# carrying encoded data rather than a name anyone typed.
#
# THE DETECTOR EXISTED AND HAD NEVER RUN. dns.TunnelScore was written, documented and unit-tested with no
# caller: the connector minted DNS events and nothing scored the name, while the engine's DNS source said
# in its own comment that tunnelling detection was live. This rule is the point where the signal becomes a
# decision, which is the part that was missing — the same gap D300 found for input.threat.
#
# It ALERTS, never blocks, and here the reason is sharper than elsewhere: this is a heuristic over a
# SINGLE query with no session context, and a rule that denied would deny NAME RESOLUTION. That presents
# to a user as "the internet is down" and to an operator as nothing in particular. An operator raises it
# to BLOCK deliberately (T1, the closed action set).
#
# The threshold arrives in the input rather than being written here, so an operator can change it without
# editing a policy — and can still see, in this rule, exactly what it is compared against.
dns_tunnel_alert if {
	input.event.dns.tunnel_score >= input.event.dns.tunnel_threshold
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

# HIPS-4 (D307): the ransomware canary fired — a threshold of planted decoy files changed within the
# window, which is the mass-change signature of encryption in progress.
#
# WITHOUT THIS RULE THE DETECTOR WAS INERT. It planted canaries, watched them, logged
# "SUSPECTED RANSOMWARE — mass canary change", emitted a high-severity event — and the default policy
# had no rule for the kind, so the decision was ALLOW and nothing reached the ledger. The detection
# existed only in stderr, which is not evidence.
#
# It ALERTS rather than acting, like everything else here (D1). Encryption in progress is exactly when
# an automatic response is most tempting and most dangerous: the mass-change signature also matches a
# legitimate bulk re-encrypt or a backup restore, and killing those mid-run is its own incident.
ransomware_suspected if {
	input.event.kind == "EVENT_KIND_RANSOMWARE_SUSPECTED"
}

alert if { ransomware_suspected }

alert if { dns_tunnel_alert }

reason := "checksum-backed PII detected above the alert threshold" if { alerting_hit }

reason := "suspicious process behavior" if {
	behavioral_alert
	not alerting_hit
}

reason := "destination matched an operator threat-intel indicator" if {
	threat_match
	not alerting_hit
	not behavioral_alert
	not ransomware_suspected
}

reason := "ransomware canaries changed en masse (HIPS-4)" if {
	ransomware_suspected
}

# The reason names the SIGNAL, not the name — a reason string carrying the queried name would put the
# tunnelled payload into the ledger, which is the disclosure this rule exists to detect (D10/D29).
reason := "DNS query name scores as a covert channel (NIPS-3)" if {
	dns_tunnel_alert
	not alerting_hit
	not behavioral_alert
	not threat_match
	not ransomware_suspected
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

# T-020/D312: a USB attachment is RECORDED but does NOT alert, and that is a deliberate choice reversed
# from a first attempt.
#
# Adding `alert if { usb_attached }` seemed obviously right — USB is the canonical careless-insider
# channel and this product's design centre. It is wrong: the event fires on ATTACHMENT, not on a copy,
# and most attachments are a keyboard, a webcam or a dock's hub. A laptop docking in the morning would
# raise a handful of alerts before anyone opened a file, which is precisely the "a detector whose output
# is mostly known-good gets muted" failure the beaconing package warns about — and a muted detector is
# worse than none.
#
# The attachment is still fully OBSERVED: the event flows the whole pipeline and its decision is recorded
# in the ledger, so "what was plugged into this machine" is answerable. An operator who wants USB to
# alert or to block writes that rule; the closed action set exists so that is their deliberate choice.
