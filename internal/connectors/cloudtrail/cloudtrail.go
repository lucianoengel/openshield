// Package cloudtrail is a third-party log-ingest connector (SIEM-4): it parses AWS CloudTrail JSON
// deliveries — the canonical cloud control-plane audit format — into structured records, so OpenShield
// can search and correlate the estate's CLOUD activity (assumed-role escalation, a disabled trail, a
// public-S3 change) beside its endpoint and network events.
//
// Like the CEF/syslog connectors it is a PURE parser: the untrusted-bytes surface (a JSON delivery from
// a bucket) is handled here and tested in ordinary Go, separate from any I/O. It DECODES over
// CloudTrail's fixed, documented schema — no heuristic field-guessing — and interprets nothing
// (whether an event is "bad" is the policy/detector's job). A body that is not a CloudTrail delivery is
// an error, never a partial record silently treated as complete (D17).
package cloudtrail

import (
	"encoding/json"
	"fmt"
	"time"
)

// MaxDelivery bounds a CloudTrail delivery file. A file is many small records; a multi-hundred-MB
// "delivery" is a memory-exhaustion vector, not a log batch.
const MaxDelivery = 32 << 20

// Record is one parsed CloudTrail event — the security-relevant subset of the documented schema. The
// full record JSON is preserved separately (Raw) for follow-on field-level hunting.
type Record struct {
	EventTime   time.Time
	EventSource string // e.g. "signin.amazonaws.com"
	EventName   string // e.g. "ConsoleLogin"
	AWSRegion   string
	SourceIP    string // sourceIPAddress — the actor's IP (a hunting pivot)
	ActorARN    string // userIdentity.arn
	ErrorCode   string // empty on success
	Account     string // recipientAccountId
	Raw         string // this record's JSON, for fidelity/field-level hunting
}

// rawDelivery / rawRecord mirror the CloudTrail JSON shape for decoding. Unknown fields are ignored
// (forward-compatible with new CloudTrail fields).
type rawDelivery struct {
	Records []json.RawMessage `json:"Records"`
}

type rawRecord struct {
	EventTime    string `json:"eventTime"`
	EventSource  string `json:"eventSource"`
	EventName    string `json:"eventName"`
	AWSRegion    string `json:"awsRegion"`
	SourceIP     string `json:"sourceIPAddress"`
	ErrorCode    string `json:"errorCode"`
	RecipientAcc string `json:"recipientAccountId"`
	UserIdentity struct {
		ARN string `json:"arn"`
	} `json:"userIdentity"`
}

// Parse decodes a CloudTrail delivery into records. It returns the records, the number SKIPPED (a
// record with no eventName is not a usable event — counted, never emitted as a partial), and an error
// when the body is oversized, not JSON, or has no `Records` array (it is not a CloudTrail delivery).
func Parse(body []byte) ([]Record, int, error) {
	if len(body) == 0 {
		return nil, 0, fmt.Errorf("cloudtrail: empty body")
	}
	if len(body) > MaxDelivery {
		return nil, 0, fmt.Errorf("cloudtrail: delivery exceeds %d bytes", MaxDelivery)
	}
	// Distinguish "not JSON" from "JSON but not a CloudTrail delivery": a CloudTrail delivery has a
	// top-level `Records` array. Its absence means the caller handed us the wrong thing — an error, not
	// an empty result that would read as "no events".
	var d rawDelivery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, 0, fmt.Errorf("cloudtrail: not JSON: %w", err)
	}
	if d.Records == nil {
		return nil, 0, fmt.Errorf("cloudtrail: no Records array — not a CloudTrail delivery")
	}

	out := make([]Record, 0, len(d.Records))
	skipped := 0
	for _, rawRec := range d.Records {
		var rr rawRecord
		if err := json.Unmarshal(rawRec, &rr); err != nil || rr.EventName == "" {
			skipped++ // a record we cannot decode or that has no event identity — counted, not emitted
			continue
		}
		rec := Record{
			EventSource: rr.EventSource,
			EventName:   rr.EventName,
			AWSRegion:   rr.AWSRegion,
			SourceIP:    rr.SourceIP,
			ActorARN:    rr.UserIdentity.ARN,
			ErrorCode:   rr.ErrorCode,
			Account:     rr.RecipientAcc,
			Raw:         string(rawRec),
		}
		if rr.EventTime != "" {
			if t, err := time.Parse(time.RFC3339, rr.EventTime); err == nil {
				rec.EventTime = t
			}
		}
		out = append(out, rec)
	}
	return out, skipped, nil
}
