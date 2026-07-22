# PCI DSS compliance pack (DLP-5).
#
# Alerts when payment-card or bank-account data — the PCI "cardholder data" scope — is present. All
# three detectors are checksum-backed (Luhn / mod-10 / mod-97), so a hit is strong evidence; the
# pack is deliberately SENSITIVE (a low threshold) because a compliance control should flag a
# validated occurrence, not wait for high confidence. Observe-only (ALERT, never BLOCK): enforcement
# is the operator's separate opt-in.
package openshield

import rego.v1

pci_detectors := {"DETECTOR_TYPE_CREDIT_CARD", "DETECTOR_TYPE_ABA_ROUTING", "DETECTOR_TYPE_IBAN"}

hit if {
	some h in input.classification
	h.type in pci_detectors
	h.confidence >= 0.5
}

decision := {"action": "ALERT", "reason": "PCI: payment-card or bank-account data detected"} if { hit }

decision := {"action": "ALLOW", "reason": "no PCI-scope data"} if { not hit }
