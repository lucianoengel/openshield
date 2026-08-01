package objectstore

import (
	"context"
	"fmt"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// THE FITNESS VERDICT (D26/D69), recorded here because a fitness test whose result is only written down
// when it passes is not a test.
//
// The question was whether a PULL/ENUMERATE producer fits the frozen core, when every existing producer is
// PUSHED. Both halves held, and the second one held for a reason that reversed the plan:
//
//  1. THE PRODUCER SEAM FITS UNCHANGED. `Next(ctx) (*corev1.Event, error)` is the shape filewatch.Watcher
//     already has, and a sweep yields objects one at a time perfectly well — the enumeration is internal
//     state behind the same interface. No core change, no strain.
//
//  2. THE CONTRACT ALREADY HAD THE EXTENSION POINT, and the plan to avoid using it was wrong. The proposal
//     said to try carrying "s3://bucket/key" in `FilesystemSubject.resolved_path` first, on the reasoning
//     that adding a message is a change to the core contract and reuse is the conservative reading of
//     D26/D69.
//
//     Trying it is what showed that backwards. `Event.target` is a oneof that EXISTS so a producer can
//     carry its own shape, and ClipboardSubject (13) and PrintSubject (14) are the precedent: each arrived
//     as a kind plus a subject. So `ObjectSubject` is the IDIOMATIC move and the URI-in-a-path was the
//     invasive one — it would have made every policy wanting "bucket = finance-exports" parse a string, and
//     made a discovered object indistinguishable from a real file except by a scheme prefix.
//
// SO THE ANSWER TO "does the pipeline absorb a new capability by adding a plugin?" IS YES, and this is the
// strongest evidence for it so far, because the producer shape was genuinely new rather than isomorphic to
// something already present. The caveat worth carrying: the claim survived because the contract had a
// designed-in growth point, not because the contract never changes. "Additive at a designed extension
// point" and "no change" are different claims, and only the first is true.

// URIScheme prefixes the EVENT ID of a discovered object. The identity itself travels structured on
// ObjectSubject; this is only to make an event id readable and collision-free across buckets.
const URIScheme = "s3://"

// ObjectURI renders the stable event identity for one object.
func ObjectURI(bucket, key string) string { return URIScheme + bucket + "/" + key }

// Sweeper enumerates a bucket once and yields one Event per object.
//
// It is deliberately ONE SWEEP rather than a loop with a ticker: the scheduling belongs to the caller, which
// already owns the process lifetime and its shutdown. A connector that owned its own timer would be a second
// place to look for "why is it not running".
type Sweeper struct {
	client  *Client
	objects []Object
	i       int
	listed  bool
	// access is the bucket's access context, probed ONCE per sweep and carried on every event from it
	// (DSPM-2). Once, because it is a property of the bucket rather than of the object: re-probing per
	// object would multiply four requests by the object count to learn the same four facts, and a sweep
	// that costs 4n requests to a rate-limited store is a sweep an operator turns off.
	access Access
	// content is where object bytes go for the sandboxed worker. It is a callback rather than a store
	// reference so this package depends on nothing but the Event contract.
	content func(eventID string, b []byte)
}

// NewSweeper returns a producer over one bucket. content receives the bytes for each event BEFORE that
// event is returned — see Next.
func NewSweeper(c *Client, content func(eventID string, b []byte)) *Sweeper {
	return &Sweeper{client: c, content: content}
}

// Next returns the next discovered object as an Event, or nil when the sweep is finished.
//
// THE CONTENT IS STORED BEFORE THE EVENT IS RETURNED, and the ordering is load-bearing for the same reason
// smtpsource.go documents: the pipeline can begin classifying the moment it has the event, so storing
// afterwards races a resolver lookup that returns nothing — and "no content" is indistinguishable from
// "clean content" downstream, which is a scan that silently did not happen. On this producer that failure is
// worse than elsewhere, because a discovery sweep's whole output is an assertion about what is NOT there.
//
// An object that cannot be read is SKIPPED AND COUNTED, not fatal: one unreadable object (a permission, a
// server-side encryption key we do not hold) must not end a sweep over ten thousand others.
func (s *Sweeper) Next(ctx context.Context) (*corev1.Event, error) {
	if !s.listed {
		// THE ACCESS PROBE RUNS BEFORE THE LISTING, so an event cannot exist without its access context.
		// Probing lazily after the first object would leave that object — and only that object — carrying an
		// unset exposure, and an UNSPECIFIED that means "not yet" is indistinguishable downstream from one
		// that means "not permitted to look".
		s.access = s.client.Access(ctx)
		objs, err := s.client.List(ctx)
		if err != nil {
			return nil, err
		}
		s.objects, s.listed = objs, true
	}
	for s.i < len(s.objects) {
		obj := s.objects[s.i]
		s.i++
		body, err := s.client.Head(ctx, obj.Key)
		if err != nil {
			// Counted as skipped so the sweep's own report stays honest about coverage.
			s.client.skipped.Add(1)
			continue
		}
		ev := s.toEvent(obj, len(body))
		if s.content != nil {
			s.content(ev.GetEventId(), body)
		}
		return ev, nil
	}
	return nil, nil
}

// toEvent builds the Event for one object. Metadata only — store, bucket, key and sizes — never content or
// a digest of it (D10/D29).
//
// bytes_examined is set from what was actually read, NOT from the ceiling, so an object smaller than the
// ceiling reports its true coverage. The gap between size_bytes and bytes_examined is the honest statement
// of how much of this object was looked at.
func (s *Sweeper) toEvent(obj Object, examined int) *corev1.Event {
	return &corev1.Event{
		EventId:     "objdisc-" + ObjectURI(s.client.cfg.Bucket, obj.Key),
		ConnectorId: "objectstore",
		Kind:        corev1.EventKind_EVENT_KIND_OBJECT_DISCOVERED,
		Target: &corev1.Event_Object{Object: &corev1.ObjectSubject{
			Store:         s.client.storeHost(),
			Bucket:        s.client.cfg.Bucket,
			Key:           obj.Key,
			SizeBytes:     obj.Size,
			BytesExamined: int64(examined),
			Access:        s.access.proto(),
		}},
	}
}

// proto renders the access context onto the event contract.
//
// The enums are mapped through an EXPLICIT switch rather than by casting the int, even though the two sets
// happen to be numbered alike today. A cast makes the wire meaning of PUBLIC depend on the declaration order
// of a Go const block, so inserting a value in the middle of one would silently relabel every stored
// finding — and this is the field an operator acts on.
func (a Access) proto() *corev1.ObjectAccess {
	return &corev1.ObjectAccess{
		Exposure:   exposureProto(a.Exposure),
		Encryption: encryptionProto(a.Encryption),
		Blocked:    a.Blocked,
		Reasons:    a.Reasons,
		Unchecked:  a.Unchecked,
	}
}

func exposureProto(e Exposure) corev1.ObjectExposure {
	switch e {
	case ExposurePrivate:
		return corev1.ObjectExposure_OBJECT_EXPOSURE_PRIVATE
	case ExposureAuthenticated:
		return corev1.ObjectExposure_OBJECT_EXPOSURE_AUTHENTICATED
	case ExposurePublic:
		return corev1.ObjectExposure_OBJECT_EXPOSURE_PUBLIC
	default:
		return corev1.ObjectExposure_OBJECT_EXPOSURE_UNSPECIFIED
	}
}

func encryptionProto(e Encryption) corev1.ObjectEncryption {
	switch e {
	case EncryptionAbsent:
		return corev1.ObjectEncryption_OBJECT_ENCRYPTION_ABSENT
	case EncryptionPresent:
		return corev1.ObjectEncryption_OBJECT_ENCRYPTION_PRESENT
	default:
		return corev1.ObjectEncryption_OBJECT_ENCRYPTION_UNSPECIFIED
	}
}

// Report describes what one sweep covered, and above all what it did NOT.
//
// A discovery feature's output is a reassuring absence: "no sensitive data found" is the answer nobody
// re-checks. So a partial sweep that reads as a complete one is this feature's most expensive failure mode,
// and the caller is given the numbers rather than a boolean.
type Report struct {
	Examined int
	Skipped  int64
	Bucket   string
	// Access is the bucket's access context as this sweep established it. It is reported alongside coverage
	// because the two answer the same question about trust: how much of what this says can be relied on.
	Access Access
}

func (s *Sweeper) Report() Report {
	return Report{Examined: s.i, Skipped: s.client.Skipped(), Bucket: s.client.cfg.Bucket, Access: s.access}
}

// String renders a report for an operator, stating coverage rather than implying it.
func (r Report) String() string {
	head := fmt.Sprintf("swept %s: %d object(s) examined, none skipped", r.Bucket, r.Examined)
	if r.Skipped > 0 {
		head = fmt.Sprintf("swept %s: %d object(s) examined, %d NOT EXAMINED (bounds or read errors) — "+
			"this sweep is PARTIAL and a clean result does not cover the whole bucket",
			r.Bucket, r.Examined, r.Skipped)
	}
	return head + "; " + r.Access.String()
}
