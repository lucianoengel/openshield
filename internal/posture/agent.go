package posture

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/attest"
)

// The AGENT-SIDE half of ZT-1 continuous attestation: open the TPM, create the AK, optionally self-enrol
// with the gateway, and re-attest on an interval.
//
// EXTRACTED HERE (CONSOLE-8e) because it lived in `cmd/openshield-fleet-agent` — the fleet SIMULATOR —
// and the endpoint agent that actually runs the pipeline could not attest at all. The alternative was to
// copy a hundred lines of TPM orchestration into a second binary, which is precisely how two agents come
// to disagree about what "attested" means. `internal/posture` already owned the enrollment handshake, the
// quote and the loop; this is the orchestration that was stranded in a main package.

// AgentAttestation is what an agent needs to attest continuously.
type AgentAttestation struct {
	// Subject is the device's CANONICAL PSEUDONYM (pseudonym.Of(agentID)) — the same derivation the
	// gateway's enrollment roster is keyed by and the access proxy resolves a client certificate to. A
	// disagreement here is silent: an unenrolled subject's quote is simply never applied.
	Subject string
	// PCRs is the platform-configuration register set the baseline covers.
	PCRs []int
	// TPMAddr is the TPM device or emulator address; empty selects the platform default.
	TPMAddr string
	// SelfEnroll asks the agent to run the network enrollment handshake before attesting. OPT-IN,
	// because a device asserting its own identity to the control plane is exactly what pre-auth tokens
	// and EK anchoring exist to constrain — enabling it by default would hand that decision to a default.
	SelfEnroll bool
	// PreAuthToken is the operator's pre-authorization for self-enrollment (D317), when the deployment
	// issues them. Empty is correct and common: a gateway that issues none ignores the field.
	PreAuthToken string
	// Interval is how often the device re-attests, so the gateway's verdict tracks its CURRENT state and
	// a drift drops it within a cycle.
	Interval time.Duration
}

// ParsePCRs reads a comma-separated PCR list, and SAYS WHAT IT SKIPPED.
//
// Skipping silently meant `0,seven` enrolled a baseline over PCR 0 alone while the operator had asked for
// two. Downstream validation cannot catch that — [0] is a perfectly valid non-empty baseline — so the
// result is an agent attesting to less than was asked with nothing to indicate it (D31).
func ParsePCRs(s string, log *slog.Logger) []int {
	var pcrs []int
	var skipped []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			skipped = append(skipped, f)
			continue
		}
		pcrs = append(pcrs, n)
	}
	if len(skipped) > 0 && log != nil {
		log.Warn("attestation PCR list has unparseable entries — a typo here NARROWS the baseline "+
			"silently, which is why this says so",
			slog.String("configured", s), slog.String("ignored", strings.Join(skipped, ", ")),
			slog.Any("attesting_over", pcrs))
	}
	return pcrs
}

// StartAgentAttestation opens the TPM, creates the AK, optionally self-enrols, and runs the attest loop
// until the context is cancelled. It BLOCKS, so callers run it in a goroutine.
//
// EVERY FAILURE IS LOGGED AND NON-FATAL. Attestation is a signal the gateway consumes, not a precondition
// for the agent existing: a device with a broken TPM should still report heartbeats, posture and
// telemetry, and be visible as a device that CANNOT ATTEST — which is far more useful to an operator than
// a machine that has vanished.
//
// Callers MUST run this off their main path. A TPM that accepts a connection and then does not answer —
// exactly what an un-started software TPM does — blocks here forever, and on the agent's main path that
// silently disabled everything else it does (D314).
func StartAgentAttestation(ctx context.Context, conn *nats.Conn, cfg AgentAttestation, log *slog.Logger) {
	if len(cfg.PCRs) == 0 {
		return
	}
	tpm, err := attest.Open(cfg.TPMAddr)
	if err != nil {
		log.Warn("attestation disabled — could not open the TPM. This device will be reported as "+
			"UNATTESTED, and a policy requiring attestation will refuse it",
			slog.String("err", err.Error()))
		return
	}
	// TPM2_STARTUP, which was missing entirely (D314) and is why nothing here could ever work against a
	// software TPM. A hardware TPM is started by platform firmware before any userspace runs, so
	// omitting it looked correct on the only device anyone had tried; a swtpm is started by whoever
	// connects to it, and until then it does not REFUSE commands — it does not answer them.
	//
	// AN ERROR HERE IS NOT FATAL: the overwhelmingly common case is the good one, where a
	// firmware-started TPM answers "already started". Treating that as a failure would disable
	// attestation on every real machine to satisfy the emulator.
	if serr := tpm.Startup(); serr != nil {
		log.Info("TPM startup returned an error, which is expected on a firmware-started TPM that is "+
			"already running — continuing", slog.String("err", serr.Error()))
	}
	ak, err := tpm.CreateAK()
	if err != nil {
		log.Warn("attestation disabled — could not create the attestation key",
			slog.String("err", err.Error()))
		_ = tpm.Close()
		return
	}

	if cfg.SelfEnroll {
		if eerr := selfEnroll(conn, tpm, ak, cfg.Subject, cfg.PCRs, cfg.PreAuthToken); eerr != nil {
			// NOT fatal, and not silent. A gateway that already holds this device in an enrollment file
			// will REJECT a re-enrollment, and that is a correct refusal rather than a reason to stop.
			// Attestation then proceeds and either works — because the device was already enrolled — or
			// does not, visibly.
			log.Warn("self-enrollment did not complete; attestation continues and will succeed only if "+
				"this device was already enrolled", slog.String("err", eerr.Error()))
		} else {
			log.Info("ZT-1 self-enrolled with the gateway (AK proven TPM-resident by credential activation)",
				slog.String("subject", cfg.Subject))
		}
	}

	interval := cfg.Interval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	log.Info("ZT-1 continuous attestation ACTIVE — the gateway's verdict comes from ITS OWN verification "+
		"of a TPM quote, never from anything this device claims",
		slog.Any("pcrs", cfg.PCRs), slog.Duration("interval", interval),
		slog.String("subject", cfg.Subject))
	AttestLoop(ctx, conn, tpm, ak, cfg.Subject, cfg.PCRs, interval, log)
}

// selfEnroll runs the network enrollment handshake, creating the EK it needs and releasing it after.
//
// THE EK IS FLUSHED, and that is not tidiness. A TPM has a small fixed number of object slots; leaving
// the endorsement key loaded after enrollment consumes one for the life of the process, and the next
// component to need a slot — the AK on a restart, another application's key — fails with a TPM
// out-of-memory error that names nothing about this program.
func selfEnroll(conn *nats.Conn, tpm *attest.TPM, ak *attest.AK, subject string, pcrs []int,
	preAuth string) error {
	ek, err := tpm.CreateEK()
	if err != nil {
		return fmt.Errorf("creating the endorsement key: %w", err)
	}
	defer func() { _ = tpm.FlushEK(ek) }()
	return EnrollWithToken(conn, tpm, ek, ak, subject, pcrs, preAuth)
}
