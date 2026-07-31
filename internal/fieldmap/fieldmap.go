// Package fieldmap gives every ingested log source one vocabulary to be hunted in (SIEM-13).
//
// THE PROBLEM IT SOLVES. Every source names the same thing differently. "Which user did this?" is
// `suser` in CEF, `userIdentityArn` in CloudTrail and `SubjectUserName` in a Windows security event. An
// analyst hunting one user across three sources has to write three queries, know three vocabularies, and
// — the part that actually bites — REMEMBER ALL THREE. A hunt that misses a source does not report that
// it missed one; it returns fewer rows and reads as a narrower blast radius. The gap in a SIEM's coverage
// looks exactly like good news.
//
// WHY MAPPING AT READ, NOT AT INGEST. A stored normalisation is a decision frozen at the moment a log
// arrived: extending the map later would leave every already-ingested log carrying the mapping of its
// own era, and the fix would need a backfill that rewrites history. Applying the map on the way OUT
// means the raw fields stay the only stored truth, an improved mapping improves every log ever ingested,
// and nothing has to be rewritten to get there. The cost is per-row work on a bounded result set, which
// is the cheaper side of that trade by a wide margin.
//
// WHAT IT DELIBERATELY IS NOT. This is a name map, not a value map. It does not parse, reformat, coerce
// types or reconcile semantics — an IP is passed through as whatever the source wrote. Claiming
// normalised VALUES would mean asserting that `SubjectUserName=CORP\alice` and `suser=alice@corp.example`
// are the same principal, which needs an identity-resolution step this product has for its own entities
// and does not have for arbitrary third-party logs. Saying so is the difference between a useful index
// and a wrong one.
package fieldmap

import (
	"sort"
	"strings"
)

// The canonical vocabulary. CLOSED and deliberately small: each name is one an analyst would actually
// pivot on during an investigation, and every addition is a promise that the map covers it across
// sources. A large vocabulary that is mostly unmapped is a worse answer than a small one that is not,
// because the analyst cannot tell which is which from the name alone.
const (
	User       = "user"        // the principal that acted
	TargetUser = "target_user" // the principal acted upon
	SourceIP   = "source_ip"
	DestIP     = "dest_ip"
	Host       = "host"
	Process    = "process"
	File       = "file"
	Action     = "action"  // what was done
	Outcome    = "outcome" // whether it succeeded
)

// aliases maps each canonical name to the source-specific keys that carry it, IN PRIORITY ORDER: the
// first key present on a log wins. Order matters where a source carries two candidates — a Windows 4688
// records both the parent (`ProcessName`) and the process that was created (`NewProcessName`), and an
// analyst asking for "the process" means the one that started.
//
// ECS DOTTED KEYS (`user.name`, `source.ip`) are here because generic JSON logs (SIEM-15) flatten to
// exactly that shape, and ECS is the convention they follow. They were MISSING when JSON ingest was
// wired, and the symptom was the one this package exists to prevent: the records ingested, they were
// searchable by their own key names, and the canonical hunt returned nothing — a coverage gap that reads
// as an absence of activity. The integration scenario caught it; no unit test could, because each side
// was correct on its own.
//
// Matching is case-insensitive because the conventions collide: CEF is lower-case (`suser`), Windows
// EventData is PascalCase (`SubjectUserName`), and CloudTrail is camelCase (`sourceIPAddress`). Requiring
// an exact case match would make the map silently miss a source whose vendor capitalised differently
// from the one this table was written against — a miss that, again, reads as fewer results rather than
// as an error.
var aliases = map[string][]string{
	User: {
		"suser",           // CEF
		"userIdentityArn", // CloudTrail (the ARN is the identity; there is no bare username)
		"SubjectUserName", // Windows EventData
		"TargetUserName",  // Windows logon events record the authenticating principal here
		"usrName",         // LEEF (SIEM-16)
		"user.name",       // ECS — the convention generic JSON logs follow (SIEM-15)
		"user",
	},
	TargetUser: {
		"duser",          // CEF
		"TargetUserName", // Windows
		"user.target.name",
		"target_user",
	},
	SourceIP: {
		"src",             // CEF and LEEF share this one
		"sourceIPAddress", // CloudTrail
		"IpAddress",       // Windows 4624/4625
		"source.ip",       // ECS
		"client.ip",       // ECS, a proxy's view of the same thing
		"src.ip",
		"source_ip",
	},
	DestIP: {
		"dst",            // CEF
		"destination.ip", // ECS
		"server.ip",      // ECS
		"dst.ip",
		"dest_ip",
	},
	Host: {
		"dvchost",         // CEF device host
		"shost",           // CEF source host
		"dhost",           // CEF destination host
		"WorkstationName", // Windows
		"Computer",
		"host.name", // ECS
		"host.hostname",
		"host",
	},
	Process: {
		"NewProcessName", // Windows 4688: the process that was CREATED, not its parent
		"sproc",          // CEF
		"ProcessName",
		"process.name", // ECS
		"process.executable",
		"process",
	},
	File: {
		"filePath", // CEF
		"fname",    // CEF
		"ObjectName",
		"file.path", // ECS
		"file.name",
		"file",
	},
	Action: {
		"act",          // CEF
		"cat",          // LEEF puts the event category here
		"eventName",    // CloudTrail
		"event.action", // ECS
		"action",
	},
	Outcome: {
		"outcome",       // CEF
		"errorCode",     // CloudTrail: empty on success, an error code on failure
		"event.outcome", // ECS
		"Status",        // Windows
	},
}

// lowerIndex is aliases with lower-cased keys, built once, so lookups are case-insensitive without
// allocating per call.
var lowerIndex = func() map[string][]string {
	out := make(map[string][]string, len(aliases))
	for canon, as := range aliases {
		lowered := make([]string, len(as))
		for i, a := range as {
			lowered[i] = strings.ToLower(a)
		}
		out[canon] = lowered
	}
	return out
}()

// Canonical returns the closed vocabulary, sorted, so a caller can present or validate it without
// duplicating the list.
func Canonical() []string {
	out := make([]string, 0, len(aliases))
	for k := range aliases {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsCanonical reports whether name is in the vocabulary.
func IsCanonical(name string) bool {
	_, ok := aliases[name]
	return ok
}

// Aliases returns the source-specific keys for a canonical name, in priority order, or nil if the name
// is not canonical. The returned slice is a copy — a caller that sorted or truncated the shared one
// would silently change every later lookup.
func Aliases(canonical string) []string {
	as, ok := aliases[canonical]
	if !ok {
		return nil
	}
	out := make([]string, len(as))
	copy(out, as)
	return out
}

// Canonicalize projects a log's raw fields onto the canonical vocabulary.
//
// It is ADDITIVE and never destructive: the caller keeps the raw fields, and this returns a separate
// view. A canonical name with no matching key is ABSENT rather than present-and-empty — "this source
// does not carry a destination IP" and "this event's destination IP was blank" are different facts, and
// collapsing them would let an analyst conclude the map covers a source it does not.
func Canonicalize(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	// One lower-cased index of the log's own keys, so the whole projection is a map lookup per alias
	// rather than a scan per alias.
	lowered := make(map[string]string, len(fields))
	for k, v := range fields {
		if v == "" {
			continue // an empty value carries nothing; see the absent-vs-blank note above
		}
		lk := strings.ToLower(k)
		if _, seen := lowered[lk]; !seen {
			lowered[lk] = v
		}
	}
	var out map[string]string
	for canon, as := range lowerIndex {
		for _, a := range as {
			if v, ok := lowered[a]; ok {
				if out == nil {
					out = make(map[string]string, len(aliases))
				}
				out[canon] = v
				break // priority order: the first alias present wins
			}
		}
	}
	return out
}
