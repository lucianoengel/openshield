package cloudtrail

import "testing"

const consoleLoginDelivery = `{"Records":[
  {"eventTime":"2026-07-22T10:15:30Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin",
   "awsRegion":"us-east-1","sourceIPAddress":"203.0.113.7","errorCode":"",
   "recipientAccountId":"123456789012","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"}},
  {"eventTime":"2026-07-22T10:16:00Z","eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy",
   "awsRegion":"us-east-1","sourceIPAddress":"203.0.113.8","errorCode":"AccessDenied",
   "recipientAccountId":"123456789012","userIdentity":{"arn":"arn:aws:iam::123456789012:role/deployer"}}
]}`

// TestParseCloudTrailDelivery (SIEM-4): a real CloudTrail delivery decodes into its documented fields.
func TestParseCloudTrailDelivery(t *testing.T) {
	recs, skipped, err := Parse([]byte(consoleLoginDelivery))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	login := recs[0]
	if login.EventName != "ConsoleLogin" || login.EventSource != "signin.amazonaws.com" ||
		login.SourceIP != "203.0.113.7" || login.ActorARN != "arn:aws:iam::123456789012:user/alice" ||
		login.AWSRegion != "us-east-1" || login.Account != "123456789012" {
		t.Fatalf("wrong ConsoleLogin fields: %+v", login)
	}
	if login.EventTime.IsZero() {
		t.Error("event time did not parse")
	}
	if recs[1].ErrorCode != "AccessDenied" {
		t.Errorf("second record error code = %q, want AccessDenied", recs[1].ErrorCode)
	}
}

// TestParseRejectsNonCloudTrail (SIEM-4): a body that is not JSON, or JSON without a Records array, is
// an error — not an empty result that would read as "no cloud events".
//
// Mutation: if Parse accepted a missing Records array (returned nil,nil), the no-Records case would not
// error → this FAILs.
func TestParseRejectsNonCloudTrail(t *testing.T) {
	for _, body := range []string{
		``,
		`this is not json`,
		`{"other":"json but no Records"}`,
		`[1,2,3]`,
	} {
		if _, _, err := Parse([]byte(body)); err == nil {
			t.Errorf("Parse(%q) returned no error — a non-CloudTrail body must be rejected", body)
		}
	}
}

// TestParseSkipsRecordWithoutEventName (SIEM-4): a record with no event identity is counted as skipped,
// never emitted as a partial record.
func TestParseSkipsRecordWithoutEventName(t *testing.T) {
	body := `{"Records":[
	  {"eventSource":"s3.amazonaws.com","awsRegion":"us-east-1"},
	  {"eventName":"GetObject","eventSource":"s3.amazonaws.com"}
	]}`
	recs, skipped, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the record with no eventName)", skipped)
	}
	if len(recs) != 1 || recs[0].EventName != "GetObject" {
		t.Errorf("records = %+v, want the one usable GetObject record", recs)
	}
}
