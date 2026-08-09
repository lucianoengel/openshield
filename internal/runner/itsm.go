package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ITSM/ticketing (SOAR-8 increment 2).
//
// The opposite semantics to the IdP responder in the same package, and the reason they do not share a
// table: an IdP action is IRREVERSIBLE, at-most-once and never retried, while a ticket is MUTABLE,
// retryable and synced in BOTH directions. Forcing one set of semantics onto the other would mean
// relaxing the guarantee that protects the irreversible half.
//
// No four-eyes here either. Opening a ticket is not an irreversible action against a person, and requiring
// an approval for it would train operators to click through approvals — which is exactly what would make
// the approval on the IdP responder meaningless. Gating is reserved for what it is for.

// ITSMConnector is one ticketing system.
type ITSMConnector struct {
	Name     string
	Endpoint string // POST to create; GET <endpoint>/<ref> for status
	Token    string
	// ClosedStatuses is the CLOSED vocabulary of remote statuses that mean the ticket is closed.
	//
	// Anything outside it is IGNORED and specifically NOT treated as closed. That direction is the whole
	// point: if a remote system renames a status or returns something unexpected, the fail-safe answer is
	// "keep investigating", not "stop".
	ClosedStatuses []string
	MinSeverity    string
	Client         *http.Client
	Timeout        time.Duration
}

// MeansClosed reports whether a remote status is one this connector declares as closed.
func (c *ITSMConnector) MeansClosed(status string) bool {
	if c == nil || status == "" {
		return false
	}
	got := strings.ToLower(strings.TrimSpace(status))
	for _, s := range c.ClosedStatuses {
		if strings.ToLower(strings.TrimSpace(s)) == got {
			return true
		}
	}
	return false
}

// TicketRequest is what a ticket is created from.
//
// METADATA ONLY: the pseudonymous subject (D23), the severity bucket and counts. No evidence content, no
// file contents, no classifier output beyond type and count — the same boundary every other export in this
// platform respects (D10/D29). A ticketing system is usually the least access-controlled place an incident
// ever reaches.
type TicketRequest struct {
	IncidentID int64  `json:"incident_id"`
	Subject    string `json:"subject"` // pseudonym
	Severity   string `json:"severity"`
	AlertCount int    `json:"alert_count"`
	HostCount  int    `json:"host_count"`
	Summary    string `json:"summary"`
}

// Ticket is the remote object's identity.
type Ticket struct {
	Ref string `json:"ref"`
	URL string `json:"url"`
}

// WHETHER A FAILED CREATE LEFT A TICKET BEHIND IS THREE DIFFERENT ANSWERS, and the caller cannot act
// sensibly on one undifferentiated error.
//
// Creation is driven by a "no ticket yet" query, so the SAFE cases simply retry on the next tick with no
// duplicate risk. But once the remote system has answered 2xx the ticket EXISTS, and every later failure
// in this function leaves it existing with nothing locally pointing at it — the next tick re-selects the
// same incident and opens a second one, forever. That is a different operational fact and it is reported
// as one.
var (
	// ErrTicketCreatedUnknownRef: the remote system ACCEPTED the create (2xx) and the response could not
	// be turned into a usable reference. The ticket DEFINITELY exists and definitely cannot be linked.
	ErrTicketCreatedUnknownRef = errors.New("runner: the ticketing system accepted the create but its " +
		"response carried no usable reference")
	// ErrTicketCreateAmbiguous: the request failed in TRANSPORT after the body was sent, so the remote
	// system may or may not have committed it. Reported as genuinely unknown — claiming either certainty
	// would be worse than saying so, because the two answers call for opposite responses.
	ErrTicketCreateAmbiguous = errors.New("runner: the ticket create failed in transport; the ticketing " +
		"system may or may not have created it")
)

// CreateTicket opens a ticket. Retry IS appropriate for this connector (unlike the IdP one): creating is
// driven by a "no ticket yet" query, so a failed attempt before the remote system commits simply retries
// on the next tick. See the sentinels above for the cases where that is NOT true.
func (c *ITSMConnector) CreateTicket(ctx context.Context, req TicketRequest) (Ticket, error) {
	var t Ticket
	body, err := json.Marshal(req)
	if err != nil {
		return t, err
	}
	resp, err := c.do(ctx, http.MethodPost, c.Endpoint, body)
	if err != nil {
		// The body was already on the wire. A cancellation, a timeout or a reset here says nothing about
		// whether the far side committed — %w keeps the underlying cause (including context.Canceled, on
		// which the loop's stop exemption depends) reachable.
		return t, fmt.Errorf("%w: %w", ErrTicketCreateAmbiguous, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// NOT ambiguous by this product's convention: a non-2xx is the remote system declining. If a
		// system returns 5xx after committing, that is a divergence only it can report.
		return t, fmt.Errorf("runner: %s create returned %s", c.Name, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return t, fmt.Errorf("%w: %s create response: %w", ErrTicketCreatedUnknownRef, c.Name, err)
	}
	if t.Ref == "" {
		return t, fmt.Errorf("%w: %s returned no ticket reference — the incident and the ticket cannot "+
			"be linked", ErrTicketCreatedUnknownRef, c.Name)
	}
	return t, nil
}

// TicketStatus polls one ticket's current status.
func (c *ITSMConnector) TicketStatus(ctx context.Context, ref string) (string, error) {
	resp, err := c.do(ctx, http.MethodGet, strings.TrimSuffix(c.Endpoint, "/")+"/"+ref, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("runner: %s status returned %s", c.Name, resp.Status)
	}
	var out struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Status, nil
}

func (c *ITSMConnector) do(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(cctx, method, url, reader)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	// The response body is read by the caller; cancel once it is closed.
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelOnClose struct {
	ReadCloser interface {
		Read([]byte) (int, error)
		Close() error
	}
	cancel context.CancelFunc
}

func (c *cancelOnClose) Read(p []byte) (int, error) { return c.ReadCloser.Read(p) }
func (c *cancelOnClose) Close() error               { defer c.cancel(); return c.ReadCloser.Close() }
