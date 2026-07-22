# GDPR compliance pack (DLP-5).
#
# Alerts on personal data — direct identifiers GDPR protects broadly: email, phone, bank account
# (IBAN), and national identifiers (SIN, EIN, SSN, CPF). Sensitive by design (a low threshold), since
# GDPR's scope is any personal data, not only high-risk categories. Observe-only (ALERT, never BLOCK).
package openshield

import rego.v1

personal_detectors := {
	"DETECTOR_TYPE_EMAIL",
	"DETECTOR_TYPE_PHONE",
	"DETECTOR_TYPE_IBAN",
	"DETECTOR_TYPE_CA_SIN",
	"DETECTOR_TYPE_EIN",
	"DETECTOR_TYPE_SSN",
	"DETECTOR_TYPE_CPF",
}

hit if {
	some h in input.classification
	h.type in personal_detectors
	h.confidence >= 0.5
}

decision := {"action": "ALERT", "reason": "GDPR: personal data detected"} if { hit }

decision := {"action": "ALLOW", "reason": "no personal data detected"} if { not hit }
