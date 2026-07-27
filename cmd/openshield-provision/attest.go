package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/lucianoengel/openshield/internal/attest"
)

// CAPTURING A DEVICE'S ATTESTATION ANCHORS OFFLINE (D314).
//
// The gateway loads device enrollments — each device's AK public key and golden PCR baseline — from a
// JSON file named by `OPENSHIELD_ATTEST_ENROLLMENTS`. The format was designed, documented, parsed,
// validated and unit-tested, and NOTHING COULD WRITE ONE: `attest.MarshalEnrollments` had no caller
// anywhere in the tree. The operator's alternative to network self-enrollment was a file they had to
// hand-author, with base64 of a TPM-marshalled public key in it.
//
// That gap had teeth because the verifier FAILS CLOSED (D85/D186). An empty verifier means every device
// is unattested, so an operator who enabled attestation and wrote a policy requiring it got a deployment
// that refused everything — with the gateway helpfully logging that enrollments were unset.
//
// WHY OFFLINE CAPTURE EXISTS AT ALL, alongside the network path: self-enrollment is a device asserting
// its own identity to the control plane. Pre-auth tokens and EK-certificate anchoring constrain that,
// but an operator who wants NO self-assertion at all — the strictest posture, and a reasonable one for a
// small high-value fleet — needs a way to capture the anchors themselves, from a device they are
// physically holding, and distribute the file out of band. This is that way.
//
// THE HONEST LIMIT, stated because it is the whole security question: run here, this reads the LOCAL
// TPM. It proves the AK is resident in the TPM this command is talking to, which is meaningful only
// because the operator ran it on the device they meant. It is not a remote proof, and it does not replace
// credential activation for a device enrolling over a network.

const attestCaptureUsage = `usage:
  openshield-provision attest-capture --subject PSEUDONYM --pcrs 0,7 [--tpm ADDR] --out FILE
      read the local TPM's AK public key and PCR baseline into a gateway enrollments file
`

func attestCapture(f map[string][]string) int {
	subject, out := one(f, "subject"), one(f, "out")
	pcrSpec := one(f, "pcrs")
	if subject == "" || out == "" || pcrSpec == "" {
		fmt.Fprint(os.Stderr, attestCaptureUsage)
		return 2
	}
	pcrs, err := parsePCRList(pcrSpec)
	if err != nil {
		return fail("%v", err)
	}

	tpm, err := attest.Open(one(f, "tpm"))
	if err != nil {
		return fail("opening the TPM: %v\n(--tpm takes a host:port for a software TPM; the default is "+
			"this machine's device)", err)
	}
	defer func() { _ = tpm.Close() }()

	ak, err := tpm.CreateAK()
	if err != nil {
		return fail("creating the attestation key: %v", err)
	}
	golden, err := tpm.ReadPCRs(pcrs)
	if err != nil {
		return fail("reading PCRs %v: %v", pcrs, err)
	}

	record := attest.AttestationEnrollment{Subject: subject, AKPublic: ak.PublicKeyBytes(), Golden: golden}
	// Validated BEFORE writing, with the SAME check the gateway applies on load. A file that the gateway
	// will refuse is worth refusing here, where the operator is present and the device is in front of
	// them — rather than at gateway startup, which is a different person on a different day.
	if err := record.Validate(); err != nil {
		return fail("%v", err)
	}
	blob, err := attest.MarshalEnrollments(mergeEnrollments(out, record))
	if err != nil {
		return fail("serialising the enrollment: %v", err)
	}
	if err := writeFile(out, blob, 0o644); err != nil {
		return fail("writing %s: %v", out, err)
	}

	fmt.Fprintf(os.Stderr, "openshield-provision: captured %s (PCRs %v) into %s\n", subject, pcrs, out)
	fmt.Fprintln(os.Stderr, "openshield-provision: the BASELINE IS WHATEVER THIS MACHINE MEASURES RIGHT "+
		"NOW. If the device is not in the state you want to attest to — mid-update, or booted differently "+
		"— you have just made that state the golden one.")
	return 0
}

// mergeEnrollments preserves the records already in the file, replacing only the subject being captured.
//
// A fleet is enrolled one device at a time, so a capture that TRUNCATED the file would unenroll every
// other device — and because the verifier fails closed, unenrolling them means they stop being able to
// attest. Silently losing the previous devices would surface as "the fleet went unattested after we
// enrolled a laptop", which is a long way from the cause. An unreadable or absent file simply starts a
// new one; a MALFORMED one is not silently discarded.
func mergeEnrollments(path string, record attest.AttestationEnrollment) []attest.AttestationEnrollment {
	out := []attest.AttestationEnrollment{record}
	blob, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	existing, err := attest.ParseEnrollments(blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-provision: %s exists but does not parse (%v) — refusing to "+
			"overwrite it; move it aside if you meant to start over\n", path, err)
		os.Exit(1)
	}
	for _, e := range existing {
		if e.Subject != record.Subject {
			out = append(out, e)
		}
	}
	return out
}

func parsePCRList(s string) ([]int, error) {
	var pcrs []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("--pcrs %q: %q is not a PCR index", s, f)
		}
		pcrs = append(pcrs, n)
	}
	if len(pcrs) == 0 {
		return nil, fmt.Errorf("--pcrs %q names no PCRs — an empty baseline attests to nothing, and the "+
			"gateway refuses such a record rather than treating it as 'anything goes'", s)
	}
	return pcrs, nil
}
