package policy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
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
			"device_posture": map[string]interface{}{
				"has_posture":    c.DevicePosture.HasPosture,
				"compliant":      c.DevicePosture.Compliant,
				"disk_encrypted": c.DevicePosture.DiskEncrypted,
				"agent_present":  c.DevicePosture.AgentPresent,
				"os_patch_tier":  int(c.DevicePosture.OSPatchTier),
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
	}
	return map[string]interface{}{
		"purpose":        st.Event.GetPurpose().String(),
		"event":          event,
		"classification": hits,
		"context":        ctx,
	}
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
