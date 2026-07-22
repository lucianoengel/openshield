# HIPAA compliance pack (DLP-5).
#
# Alerts on protected health information (PHI): direct health-data keywords, the US National Provider
# Identifier and the UK NHS patient number (healthcare identifiers), and the SSN (a HIPAA identifier).
# Sensitive by design (a low threshold) — a compliance control flags a validated PHI occurrence.
# Observe-only (ALERT, never BLOCK).
package openshield

import rego.v1

phi_detectors := {
	"DETECTOR_TYPE_HEALTH_DATA",
	"DETECTOR_TYPE_NPI",
	"DETECTOR_TYPE_UK_NHS",
	"DETECTOR_TYPE_SSN",
}

hit if {
	some h in input.classification
	h.type in phi_detectors
	h.confidence >= 0.5
}

decision := {"action": "ALERT", "reason": "HIPAA: protected health information detected"} if { hit }

decision := {"action": "ALLOW", "reason": "no PHI detected"} if { not hit }
