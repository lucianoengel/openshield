package policy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/attack"
	"github.com/lucianoengel/openshield/internal/behavioral"
	"github.com/lucianoengel/openshield/internal/casb"
	"github.com/lucianoengel/openshield/internal/connectors/dns"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/exfil"
)

// actionNames is the CLOSED mapping between the enum and the bare names a policy
// uses. It is explicit rather than derived from the proto so that adding an enum
// value forces a deliberate edit here — and the ACTION_UNSPECIFIED zero value is
// intentionally ABSENT: a policy cannot select "unspecified", and an unmapped
// name is an error, never a default.
var actionNames = map[string]corev1.Action{
	"ALLOW":            corev1.Action_ACTION_ALLOW,
	"ALERT":            corev1.Action_ACTION_ALERT,
	"BLOCK":            corev1.Action_ACTION_BLOCK,
	"QUARANTINE_LOCAL": corev1.Action_ACTION_QUARANTINE_LOCAL,
	"ENCRYPT_LOCAL":    corev1.Action_ACTION_ENCRYPT_LOCAL,
	// Network verdict (N1/D69): a policy can emit REDIRECT to coach a flow.
	"REDIRECT": corev1.Action_ACTION_REDIRECT,
	// Process control (Phase E / HIPS): the deliberate T1 action-set expansion (D14).
	"DENY_EXEC":    corev1.Action_ACTION_DENY_EXEC,
	"KILL_PROCESS": corev1.Action_ACTION_KILL_PROCESS,
}

func actionFromName(name string) (corev1.Action, bool) {
	a, ok := actionNames[name]
	return a, ok
}

// buildInput assembles the document handed to Rego. Context is null in Phase 1
// (D28 seam). Classification carries type + confidence + count only — the same
// summary shape that is allowed to leave the host; the policy sees no content.
func buildInput(st *core.State) map[string]interface{} {
	var hits []interface{}
	if lc := st.Classification; lc != nil {
		agg := map[corev1.DetectorType]struct {
			maxConf float64
			count   uint32
		}{}
		for _, m := range lc.GetMatches() {
			e := agg[m.GetDetectorType()]
			if m.GetConfidence() > e.maxConf {
				e.maxConf = m.GetConfidence()
			}
			e.count++
			agg[m.GetDetectorType()] = e
		}
		for dt, v := range agg {
			hits = append(hits, map[string]interface{}{
				"type":       dt.String(),
				"confidence": v.maxConf,
				"count":      int(v.count),
			})
		}
	}
	// Context is nil in the observe-only default; a new-shape capability
	// (peer-UEBA, D26) resolves it via the dispatcher hook, and Policy consults
	// its risk score. Only the boundary-safe risk fields are exposed — a closed
	// typed set (D28), not the whole Context.
	var ctx interface{}
	if c := st.Context; c != nil {
		ctx = map[string]interface{}{
			"risk_score":     c.RiskScore,
			"has_risk_score": c.HasRiskScore,
			// Zero-Trust identity context (D85): identity/role/device_posture, a
			// boundary-safe closed projection (never the whole Context). A policy
			// decides identity-aware authorization; absent posture (has_posture
			// false) lets the policy fail CLOSED for access — the tamper-lockout.
			"identity": c.Identity,
			"role":     c.Role,
			// SOAR-7 / HIPS-3 inc 2b: the coordinated-response verb in effect for this subject, as a
			// closed-enum NAME. A policy can refuse an exec for a CONTAINed entity; one that does not read
			// this is unaffected by any intent, by design.
			"response_intent":     c.ResponseIntent.String(),
			"has_response_intent": c.HasResponseIntent,
			"device_posture": map[string]interface{}{
				"has_posture":    c.DevicePosture.HasPosture,
				"compliant":      c.DevicePosture.Compliant,
				"disk_encrypted": c.DevicePosture.DiskEncrypted,
				"agent_present":  c.DevicePosture.AgentPresent,
				"os_patch_tier":  int(c.DevicePosture.OSPatchTier),
				"attested":       c.DevicePosture.Attested,
				// PLAT-6 inc 3: the endpoint's own answer to whether its binaries are the published
				// ones, as a NAME rather than a number so a policy reads
				// `binary_integrity == "VERIFIED"` and an unconfigured endpoint ("UNCHECKED") never
				// satisfies it by accident. Self-reported — weigh it as evidence, not proof.
				"binary_integrity": c.DevicePosture.Binaries.String(),
			},
		}
	}
	event := map[string]interface{}{"kind": st.Event.GetKind().String()}
	// For a network event, expose the requested service host/method/path so a policy
	// can microsegment (allow a role to a service, D88). This reaches only the LOCAL
	// in-process policy — telemetry still REDACTS the URL path (D77), and the Decision
	// carries no content (D14), so local exposure is not a boundary crossing.
	if ns := st.Event.GetNetwork(); ns != nil {
		event["host"] = ns.GetSniHost()
		event["method"] = ns.GetHttpMethod()
		event["path"] = ns.GetHttpPath()
		// Content-aware CASB (DLP-2): a content-free derivation of the destination host +
		// method (like exfil_channel below is derived from a path), so a policy can block
		// sensitive content bound for an UNSANCTIONED cloud upload while allowing a
		// sanctioned one. The content half is input.classification (worker DLP hits); the
		// policy ANDs the two. Absent when no catalog is configured or the host is not a
		// catalogued service (nil match) — existing pipelines unaffected.
		if m := casb.Classify(ns.GetSniHost(), ns.GetHttpPath(), ns.GetHttpMethod()); m != nil {
			event["cloud"] = map[string]interface{}{
				"service":    m.Service,
				"category":   m.Category,
				"sanctioned": m.Sanctioned,
				"upload":     m.Upload,
			}
		}
		// DNS TUNNELLING (NIPS-3). `dns.TunnelScore` was written, unit-tested and had NO CALLER: the
		// connector minted a DNS event and nothing ever scored the name, so a covert-channel detector
		// had never run on a live query while the engine's DNS source claimed in its own doc comment
		// that it was live. Third instance of the shape D300 and D301 found — a signal that never
		// becomes a decision.
		//
		// COMPUTED HERE, not in the connector. This is the layer whose job is deriving typed policy
		// inputs (casb.Classify above, behavioral.Analyze below); scoring in ToEvent would put the
		// number on the wire (a proto change) and would let the CONNECTOR decide how suspicious
		// something is. The name is metadata the parser already produced, so scoring its length and
		// entropy is arithmetic and needs no sandboxed worker (D29 is about parsing attacker bytes).
		//
		// UNDER ITS OWN KEY, not `behavioral`. That one is a PROCESS verdict whose siblings — lolbin,
		// lineage, encoded command — do not apply to a query, so reusing it would emit `lolbin: false`:
		// false rather than absent, which reads as "checked and clean". It would also start firing every
		// operator policy written against behavioral.score on DNS traffic without anyone editing a
		// policy. Absent for every event that is not a DNS query, exactly as `cloud` is.
		if st.Event.GetKind() == corev1.EventKind_EVENT_KIND_DNS_QUERY {
			// THE THRESHOLD TRAVELS WITH THE SCORE so the comparison lives in the POLICY, where an
			// operator reading default.rego can see it, rather than buried in Go where they cannot.
			// The detector's job is to produce a number; deciding what counts as suspicious enough to
			// act on is the policy's.
			event["dns"] = map[string]interface{}{
				"tunnel_score":     dns.TunnelScore(ns.GetSniHost()),
				"tunnel_threshold": dns.TunnelThreshold(),
			}
		}
	}
	// For a filesystem event, expose the exfil channel of the write (DLP-2): a
	// content-free derivation of the path (like the behavioral analysis below), so a
	// policy can escalate a sensitive write to a cloud-sync/removable channel
	// differently from a local one. Path-derived only — no content, no file access.
	if fs := st.Event.GetFilesystem(); fs != nil {
		if p := fs.GetResolvedPath(); p != "" {
			event["exfil_channel"] = exfil.Classify(p).String()
		}
	}
	// A CLIPBOARD copy is an exfil channel too (DLP-2a), but it has NO path — so the channel comes from the
	// event KIND, not from exfil.Classify. Feeding the path classifier a pseudo-path ("clipboard://…") would
	// invent a filesystem entity that other code would eventually try to open. A channel-aware policy now
	// gates copy-paste with the same rule it uses for a cloud-sync write, knowing nothing clipboard-specific.
	if cb := st.Event.GetClipboard(); cb != nil {
		event["exfil_channel"] = exfil.ChannelClipboard.String()
		event["clipboard_bytes"] = int(cb.GetByteCount())
		event["display_server"] = cb.GetDisplayServer()
	}
	// A PRINT job (DLP-2b) is likewise a pathless exfil channel. The printer and submitting user are
	// metadata a policy can gate on ("no sensitive printing to the lobby printer"); the document's title is
	// deliberately absent from the contract, because a title is often the sensitive fact itself.
	if pr := st.Event.GetPrint(); pr != nil {
		event["exfil_channel"] = exfil.ChannelPrint.String()
		event["printer"] = pr.GetPrinter()
		event["print_bytes"] = int(pr.GetByteCount())
		event["job_user"] = pr.GetJobUser()
	}
	// A USB ATTACHMENT (T-020/D313). The subject has existed since T-020 and reached the policy input
	// NEVER — `GetUsb` had exactly one non-generated caller in the tree, a log line. So the event flowed
	// the whole pipeline and arrived at Rego indistinguishable from anything else: a policy could not tell
	// a memory stick from a file write, and the sentence in default.rego saying an operator who wants USB
	// to block "writes that rule" named a rule that could not be written.
	//
	// WHAT IS EXPOSED IS THE DEVICE'S IDENTITY, NOT ITS BEARER. Vendor and product are model identifiers —
	// the same for every unit of that model, so they say "a SanDisk stick", never "whose". The serial is
	// the pseudonym, keyed at the producer (D23), so a policy can say "the same device again" without the
	// engine ever holding the real serial. That is the whole point of pseudonymising at the source.
	if u := st.Event.GetUsb(); u != nil {
		event["usb"] = map[string]interface{}{
			"vendor_id":        u.GetVendorId(),
			"product_id":       u.GetProductId(),
			"serial_pseudonym": u.GetSerialPseudonym(),
		}
		// The same channel vocabulary a removable-media WRITE gets, so one rule covers both: an operator
		// writing "nothing sensitive to removable" should not need to know that an attachment and a copy
		// arrive as different event kinds.
		event["exfil_channel"] = exfil.ChannelRemovable.String()
	}
	// AN OBJECT DISCOVERED AT REST (DSPM-1/DSPM-2), and this is the USB defect again (D313): ObjectSubject
	// has existed since the discovery sweep shipped and `GetObject` had exactly ONE caller in the whole
	// tree — a test. So the bucket and key never reached Rego, and sweep.go's own doc comment justified the
	// structured subject by saying it spares "every policy that wants `bucket = finance-exports`" from
	// parsing a string. That rule could not be written at all.
	//
	// THE EXPOSURE IS THE FIELD THAT RANKS THE FINDING. Sensitive data in a bucket is a fact; sensitive data
	// in a bucket the internet can read is an incident, and only the policy layer can hold the opinion about
	// which. It is exposed as a NAME rather than a number so a rule reads `exposure == "PUBLIC"` — and so
	// that "UNSPECIFIED", meaning nobody could determine it, cannot be mistaken for the safe end of a scale.
	// A policy that wants to treat not-knowing as a finding writes that; one that ignores the field is
	// unaffected, which is what keeps this additive.
	if ob := st.Event.GetObject(); ob != nil {
		obj := map[string]interface{}{
			"store":          ob.GetStore(),
			"bucket":         ob.GetBucket(),
			"key":            ob.GetKey(),
			"size_bytes":     int(ob.GetSizeBytes()),
			"bytes_examined": int(ob.GetBytesExamined()),
		}
		if ac := ob.GetAccess(); ac != nil {
			obj["exposure"] = ac.GetExposure().String()
			obj["encryption"] = ac.GetEncryption().String()
			obj["blocked"] = ac.GetBlocked()
			// Whether the access picture is COMPLETE, as a boolean a rule can gate on without walking a
			// list of prose. The prose stays on the event for the analyst; the policy gets the predicate.
			obj["access_complete"] = len(ac.GetUnchecked()) == 0
		}
		event["object"] = obj
		// NO exfil_channel IS SET, and that is deliberate. The clipboard, print and USB arms above all
		// assign one because each IS a movement of data off the endpoint. A discovery sweep is not: nothing
		// left anywhere, somebody looked. Tagging it `cloud_sync` would have been the tidy-looking move and
		// would have silently widened every existing "nothing sensitive to cloud sync" rule to fire on data
		// that has been sitting still for two years — changing what an operator's already-written policy
		// means without them touching it. Exposure is the ranking signal here; a channel would be a lie
		// about what happened.
	}
	// For a process-exec event, expose the exec path, args, and parent path so a
	// behavioral policy can decide on LOLBins and process lineage (Phase E, HIPS). Exec
	// metadata only (D10/D29) — no process memory or file content.
	if ps := st.Event.GetProcess(); ps != nil {
		event["exec_path"] = ps.GetExecPath()
		event["parent_path"] = ps.GetParentPath()
		args := make([]interface{}, 0, len(ps.GetArgs()))
		for _, a := range ps.GetArgs() {
			args = append(args, a)
		}
		event["args"] = args
		// HIPS behavioral analysis (Phase E, HIPS-5): the LOLBin / suspicious-lineage / encoded-
		// command detection runs HERE, in the engine, on process METADATA only — it is pure and
		// content-free, so it needs no sandboxed worker (D29 is about content parsing, not
		// metadata). Its verdict is exposed as a typed policy input; the POLICY decides the action
		// (ALERT/KILL — the closed set, T1), never the detector. This is the seam that turns the
		// built-but-unwired behavioral detectors into a running detection path.
		f := behavioral.Analyze(ps.GetExecPath(), ps.GetParentPath(), ps.GetArgs())
		event["behavioral"] = map[string]interface{}{
			"score":              f.Score,
			"lolbin":             f.LOLBin,
			"suspicious_lineage": f.SuspiciousLineage,
			"encoded_command":    f.EncodedCommand,
		}
	}
	// Network threat-intel matches (NIPS-2): a distinct axis from classification —
	// a known-bad destination/request, so a policy can prevent the flow. Absent
	// when no threat engine ran or nothing matched (a threat rule then denies
	// nothing on its own — fail open, D73).
	var threat interface{}
	if tc := st.Threats; tc != nil && len(tc.GetMatches()) > 0 {
		cats := map[string]int{}
		matches := make([]interface{}, 0, len(tc.GetMatches()))
		for _, m := range tc.GetMatches() {
			cats[m.GetCategory().String()]++
			matches = append(matches, map[string]interface{}{
				"category":     m.GetCategory().String(),
				"confidence":   m.GetConfidence(),
				"indicator_id": m.GetIndicatorId(),
			})
		}
		threat = map[string]interface{}{"matches": matches, "categories": cats}
	}
	// MITRE ATT&CK techniques (SIEM-7): a content-free derivation of the SAME signals
	// above — credential detector types, threat categories, the exfil channel, and
	// the behavioral findings — so a policy can route on a technique and SIEM/XDR can
	// group by it. Absent when no signal maps to a technique.
	var attackTechs interface{}
	if ids := attack.IDs(attackSignals(st)); len(ids) > 0 {
		techs := make([]interface{}, len(ids))
		for i, id := range ids {
			techs[i] = id
		}
		attackTechs = map[string]interface{}{"techniques": techs}
	}
	return map[string]interface{}{
		"purpose":        st.Event.GetPurpose().String(),
		"event":          event,
		"classification": hits,
		"context":        ctx,
		"threat":         threat,
		"attack":         attackTechs,
	}
}

// attackSignals gathers the content-free detection signals from the state for the
// ATT&CK mapping (SIEM-7).
func attackSignals(st *core.State) attack.Signals {
	var s attack.Signals
	if lc := st.Classification; lc != nil {
		for _, m := range lc.GetMatches() {
			s.DetectorTypes = append(s.DetectorTypes, m.GetDetectorType())
		}
	}
	if tc := st.Threats; tc != nil {
		for _, m := range tc.GetMatches() {
			s.ThreatCategories = append(s.ThreatCategories, m.GetCategory())
		}
	}
	if fs := st.Event.GetFilesystem(); fs != nil {
		if p := fs.GetResolvedPath(); p != "" {
			s.ExfilChannel = exfil.Classify(p).String()
		}
	}
	// DLP-2a: the clipboard channel, assigned by kind (see buildInput above for why not by path). This also
	// makes a sensitive copy map to the exfil-over-physical-medium/cloud ATT&CK techniques the same way a
	// channelled file write does.
	if cb := st.Event.GetClipboard(); cb != nil {
		s.ExfilChannel = exfil.ChannelClipboard.String()
	}
	if pr := st.Event.GetPrint(); pr != nil {
		s.ExfilChannel = exfil.ChannelPrint.String()
	}
	if ps := st.Event.GetProcess(); ps != nil {
		f := behavioral.Analyze(ps.GetExecPath(), ps.GetParentPath(), ps.GetArgs())
		s.LOLBin = f.LOLBin != ""
		s.EncodedCommand = f.EncodedCommand
		s.SuspiciousLineage = f.SuspiciousLineage
	}
	return s
}

// confidenceFrom takes the policy's confidence if it supplied one, else the
// classification's max. Either way it is clamped strictly below 1.0: a Decision
// never reports certainty (D4).
//
// OPA returns Rego numbers as json.Number, not float64. Reading only float64
// would silently ignore every policy-supplied confidence and fall back to the
// classification max — which would make the clamp untested and a policy's
// intent lost. Both forms are handled.
func confidenceFrom(raw map[string]interface{}, st *core.State) float64 {
	c := maxClassificationConfidence(st)
	if v, ok := regoFloat(raw["confidence"]); ok {
		c = v
	}
	return clampSubCertain(c)
}

// regoFloat reads a number from a Rego result, accepting both json.Number (what
// OPA actually returns) and float64 (defensive).
func regoFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	default:
		return 0, false
	}
}

func maxClassificationConfidence(st *core.State) float64 {
	var max float64
	if lc := st.Classification; lc != nil {
		for _, m := range lc.GetMatches() {
			if m.GetConfidence() > max {
				max = m.GetConfidence()
			}
		}
	}
	return clampSubCertain(max)
}

// clampSubCertain caps confidence just under 1.0. Classification is
// probabilistic; a Decision that reports 1.0 would invite whatever consumes it
// to treat classification as truth, which D4 forbids.
func clampSubCertain(c float64) float64 {
	const ceiling = 0.99
	if c > ceiling {
		return ceiling
	}
	if c < 0 {
		return 0
	}
	return c
}

// --- injected non-determinism, kept OUT of the policy ---

type timestamp struct{ t time.Time }

func (ts timestamp) proto() *timestamppb.Timestamp { return timestamppb.New(ts.t) }

func nowUTC() timestamp { return timestamp{t: time.Now().UTC()} }

func newDecisionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "dec_" + hex.EncodeToString(b[:])
}

// MappedActionsForTest exposes the closed action table so a test can assert it
// is complete — every enum value except the unspecified zero mapped exactly
// once. Kept next to the table it guards.
func MappedActionsForTest() map[string]corev1.Action { return actionNames }
