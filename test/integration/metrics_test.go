//go:build integration

package integration

import (
	"io"
	"net/http"
	"testing"
	"time"
)

// THE DISCARD COUNTERS ARE OBSERVABLE (D348, OPENSHIELD_METRICS_ADDR).
//
// Eight counters were incremented and rendered by nothing — the whole external-log ingest path (CEF,
// CloudTrail, WEF), entity-graph resolve failures, retention record failures. Each was written with a
// comment saying it existed so a discard would not be silent, and one claimed in a comment to be on
// `/metrics` already, with dashboards depending on it.
//
// So this asserts on what a SCRAPE actually returns from a running server. A unit test over the
// handler proves the strings are formatted; only the real endpoint proves an operator can reach them.

// scrapeMetrics fetches the metrics endpoint.
func scrapeMetrics(t *testing.T, addr string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(Ctx(t), http.MethodGet, "http://"+addr+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("scraping %s: %v", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestTheIngestDiscardCountersAreScrapable.
func TestTheIngestDiscardCountersAreScrapable(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	metricsAddr := "127.0.0.1:" + freePort(t)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_METRICS_ADDR=" + metricsAddr,
	})
	srv.WaitForOutput("subscribing to telemetry", 90*time.Second)
	waitTCP(t, metricsAddr, 60*time.Second)

	body := scrapeMetrics(t, metricsAddr)

	// Every counter that exists so a discard is not silent. A missing one here means the discard IS
	// silent, whatever the code comment beside it says.
	for _, want := range []string{
		"openshield_cef_ingested_total",
		"openshield_cef_dropped_total",
		"openshield_cloudtrail_ingested_total",
		"openshield_cloudtrail_dropped_total",
		"openshield_wef_ingested_total",
		"openshield_wef_dropped_total",
		"openshield_entity_resolve_failures_total",
		"openshield_retention_record_failures_total",
	} {
		if !contains(body, want) {
			t.Errorf("%s is not on /metrics. It is incremented in the ingest path, so without it an "+
				"operator cannot tell a quiet estate from one whose logs are being discarded", want)
		}
		// AND WITH HELP TEXT. A number with no explanation is one an operator has to read the source
		// to interpret, at whatever hour they first see it move.
		if !contains(body, "# HELP "+want+" ") {
			t.Errorf("%s has no HELP line", want)
		}
	}

	// NO SYSLOG LISTENER IS CONFIGURED HERE, so its counters must be ABSENT rather than zero. A
	// listener that is not running and one that is refusing nothing are different claims, and a
	// dashboard alerting on "rate_limited == 0" cannot distinguish them.
	if contains(body, "openshield_syslog_rate_limited_total") {
		t.Error("a syslog listener counter is reported when no listener is configured — a dashboard " +
			"cannot then tell 'refusing nothing' from 'not running'")
	}
}

// TestAConfiguredSyslogListenerReportsItsRefusalCounters is the other half: when the listener IS
// running, its counters appear. Without this, the absence assertion above is satisfied by counters
// that are never emitted under any condition.
func TestAConfiguredSyslogListenerReportsItsRefusalCounters(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	metricsAddr := "127.0.0.1:" + freePort(t)
	syslogAddr := "127.0.0.1:" + freePort(t)
	setDynamic(t, stack, "OPENSHIELD_CEF_SYSLOG_LISTEN", syslogAddr)

	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_METRICS_ADDR=" + metricsAddr,
	})
	srv.WaitForOutput("CEF-over-syslog listener on", 90*time.Second)
	waitTCP(t, metricsAddr, 60*time.Second)

	// The listener is published asynchronously as it binds, so allow the scrape to catch up rather
	// than racing it — a scrape that lost the race would report an absent counter, which is exactly
	// the state the previous test asserts and would make this one pass for the wrong reason.
	var body string
	Eventually(t, 60*time.Second, "the running listener's counters to appear on /metrics", func() bool {
		body = scrapeMetrics(t, metricsAddr)
		return contains(body, "openshield_syslog_rate_limited_total")
	})
	if !contains(body, "openshield_syslog_unparsed_total") {
		t.Errorf("the listener's unparsed counter is missing while its rate-limit counter is "+
			"present:\n%s", body)
	}
}
