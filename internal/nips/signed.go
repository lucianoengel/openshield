package nips

import (
	"crypto/ed25519"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync/atomic"
)

// SIGNED IOC FEEDS (SOAR-5).
//
// The feed decides what the gateway BLOCKS and, since SOAR-5, what the platform calls a threat. Unsigned,
// that authority belongs to whatever can write the file or answer the URL. A detached ed25519 signature
// over the feed's exact bytes moves it back to whoever holds the key.
//
// THE ORDERING IS THE WHOLE POINT: verification runs BEFORE parsing.
//
//   - The parser is the untrusted-input surface. Verifying afterwards would mean a hostile feed had
//     already been through it, which is the code an attacker actually wants to reach.
//   - Rejection is TOTAL. Per-line or per-indicator verification would apply exactly the attacker-chosen
//     subset that verified — they would drop the indicators naming their own infrastructure and keep
//     everything else, and the store would look healthy while being blind in the one place that matters.
//
// Signing proves ORIGIN, not correctness: a validly signed bad feed is indistinguishable from a good one.
// That is why a threat-intel hit ANNOTATES rather than enforces (SOAR-5's enrichment), and why the same
// caveat is recorded for the risk-signing key (SEC-1).

// ErrFeedSignature means the feed's bytes do not match its signature — or a signature was required and
// none was supplied. The feed is refused as a whole and never parsed.
var ErrFeedSignature = errors.New("nips: IOC feed signature does not verify")

// Format names how a feed's bytes are structured. It is passed EXPLICITLY and never sniffed from the
// content: letting a crafted file choose which parser handles it is a free surface to close.
type Format string

const (
	// FormatNative is the original whitespace format: "<kind> <indicator>", # comments.
	FormatNative Format = "native"
	// FormatCSV is "kind,indicator" (a trailing description column is ignored) — the shape most public
	// feeds ship in.
	FormatCSV Format = "csv"
)

// Indicator is one IOC as data: a kind and a value. It exists so a feed can round-trip through a list —
// enumerated for persistence, rebuilt for matching — which is what keeps MATCHING to one implementation
// shared by the inline engine and the analytical path, instead of one per consumer.
type Indicator struct {
	Kind  string // domain | ip | cidr | uri
	Value string
}

// Indicators enumerates the feed's contents in a stable order.
//
// Stable so a caller can diff or digest two feeds; map iteration order would make a persisted feed look
// different on every ingest.
func (f *Feed) Indicators() []Indicator {
	if f == nil {
		return nil
	}
	out := make([]Indicator, 0, f.Size())
	for d := range f.domains {
		out = append(out, Indicator{Kind: KindDomain, Value: d})
	}
	for ip := range f.ips {
		out = append(out, Indicator{Kind: KindIP, Value: ip})
	}
	for _, n := range f.cidrs {
		out = append(out, Indicator{Kind: KindCIDR, Value: n.String()})
	}
	for _, u := range f.uris {
		out = append(out, Indicator{Kind: KindURI, Value: u})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// BuildFeed reconstructs a Feed from indicators — the inverse of Indicators().
//
// It runs the SAME validation the parsers do (addIndicator), so a value that could not have been parsed
// cannot enter through this door either: the store is not a trusted source just because it is ours.
func BuildFeed(indicators []Indicator) (*Feed, error) {
	f := &Feed{domains: map[string]struct{}{}, ips: map[string]struct{}{}}
	for i, in := range indicators {
		if err := addIndicator(f, strings.ToLower(in.Kind), in.Value, fmt.Sprintf("indicator %d", i)); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// parseInvocations counts how many times the PARSER has been entered.
//
// It exists so the verify-before-parse ordering is TESTABLE rather than assumed. The parser is a pure
// function, so "a bad feed was refused" looks identical whether verification ran first or last — and the
// ordering is the actual security property, since the parser is the surface an attacker wants to reach.
// An atomic increment on a path that runs once per feed ingest costs nothing.
var parseInvocations atomic.Uint64

// ParseFormat parses a feed in the NAMED format.
func ParseFormat(r io.Reader, format Format) (*Feed, error) {
	parseInvocations.Add(1)
	switch format {
	case FormatNative, "":
		return ParseFeed(r)
	case FormatCSV:
		return parseCSVFeed(r)
	default:
		return nil, fmt.Errorf("nips: unknown feed format %q (want %s|%s)", format, FormatNative, FormatCSV)
	}
}

// parseCSVFeed reads "kind,indicator[,anything]". A '#' comment line and a blank line are skipped, as in
// the native format. Extra columns (a description, a first-seen date) are IGNORED rather than rejected,
// because public feeds carry them and refusing the row would make the format unusable — but the first two
// columns are mandatory, so a truncated row is an error and never a silently-skipped indicator.
func parseCSVFeed(r io.Reader) (*Feed, error) {
	f := &Feed{domains: map[string]struct{}{}, ips: map[string]struct{}{}}
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // variable width: the trailing columns are feed-specific
	cr.Comment = '#'
	cr.TrimLeadingSpace = true
	row := 0
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		row++
		if err != nil {
			return nil, fmt.Errorf("nips: csv feed row %d: %w", row, err)
		}
		if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
			continue
		}
		if len(rec) < 2 {
			return nil, fmt.Errorf("nips: csv feed row %d: want 'kind,indicator', got %q", row, rec)
		}
		kind := strings.ToLower(strings.TrimSpace(rec[0]))
		indicator := strings.TrimSpace(rec[1])
		if kind == "" && indicator == "" {
			continue
		}
		if err := addIndicator(f, kind, indicator, fmt.Sprintf("csv row %d", row)); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// VerifyAndParse verifies a detached signature over data and only then parses it.
//
// A nil/empty public key means the deployment has not configured feed authentication: the feed parses
// unsigned, as it always did. That is a deliberate configuration CHOICE rather than a silent default —
// existing deployments keep working, and the absence is visible in config rather than implied by code.
func VerifyAndParse(data, sig []byte, pub ed25519.PublicKey, format Format) (*Feed, error) {
	if len(pub) != 0 {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("nips: feed verification key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
		}
		if len(sig) == 0 {
			return nil, fmt.Errorf("%w: no signature supplied but a key is configured", ErrFeedSignature)
		}
		if !ed25519.Verify(pub, data, sig) {
			// RETURN BEFORE PARSING. Nothing below this line may run on unverified bytes.
			return nil, ErrFeedSignature
		}
	}
	return ParseFormat(strings.NewReader(string(data)), format)
}

// LoadSignedFeed reads a feed and its detached signature from disk and verifies before parsing. sigPath
// may be empty when no key is configured.
func LoadSignedFeed(path, sigPath string, pub ed25519.PublicKey, format Format) (*Feed, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("nips: reading IOC feed: %w", err)
	}
	var sig []byte
	if sigPath != "" {
		if sig, err = os.ReadFile(sigPath); err != nil {
			return nil, nil, fmt.Errorf("nips: reading IOC feed signature: %w", err)
		}
	}
	f, err := VerifyAndParse(data, sig, pub, format)
	if err != nil {
		return nil, nil, err
	}
	return f, data, nil
}
