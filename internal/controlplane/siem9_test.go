package controlplane_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SIEM-9: one listener, both formats.
//
// An estate rarely emits a single log format, and making an operator run a port per format is how a log
// source ends up not onboarded at all — which is a detection gap that looks like a configuration choice.

func sendSyslog(t *testing.T, addr, line string) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
}

// TestOneListenerIngestsBothCEFAndRFC5424.
//
// Mutation: drop the RFC 5424 fallback → the modern-syslog line is counted as dropped and never stored →
// FAILS.
func TestOneListenerIngestsBothCEFAndRFC5424(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.RunCEFSyslog(ctx, "127.0.0.1:0") }()
	waitFor(t, func() bool { return srv.CEFListenAddr() != "" })
	addr := srv.CEFListenAddr()

	// CEF arrives INSIDE an RFC 5424 frame — which is exactly why CEF is tried first: this line is
	// legitimately both formats, and the CEF reading is the more specific one.
	sendSyslog(t, addr, `<134>1 2026-07-26T10:00:00Z fw02 firewall - - - `+
		`CEF:0|Acme|Firewall|1.0|100|Blocked|5|src=10.0.0.9 dst=203.0.113.5`)
	sendSyslog(t, addr, `<165>1 2026-07-26T14:05:09.123Z fw01.corp sshd 4321 SESSION `+
		`[auth@32473 user="alice" result="fail"] Failed password for alice`)

	waitFor(t, func() bool {
		logs, err := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{Limit: 50})
		return err == nil && len(logs) >= 2
	})
	logs, err := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var sawCEF, sawSyslog bool
	for _, l := range logs {
		switch l.Vendor {
		case "Acme":
			sawCEF = true
		case "syslog":
			sawSyslog = true
			if l.Product != "sshd" || l.Severity != "notice" || l.SourceHost != "fw01.corp" {
				t.Errorf("rfc5424 record = %+v, want sshd/notice/fw01.corp", l)
			}
			if l.Message != "Failed password for alice" {
				t.Errorf("message = %q", l.Message)
			}
		}
	}
	if !sawCEF {
		t.Error("the CEF line stopped being ingested — the fallback must not displace the primary format")
	}
	if !sawSyslog {
		t.Error("the RFC 5424 line was not ingested — an estate emitting modern syslog would be silently " +
			"unonboarded, which is a detection gap that looks like a configuration choice")
	}
}

// TestStructuredDataIsHuntableLikeACEFExtension is why this format was worth adding: an SD element and a
// CEF extension become the SAME searchable key/value, so an analyst hunts once across both.
//
// Mutation: store structured data anywhere but `fields` → the hunt returns nothing → FAILS.
func TestStructuredDataIsHuntableLikeACEFExtension(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.RunCEFSyslog(ctx, "127.0.0.1:0") }()
	waitFor(t, func() bool { return srv.CEFListenAddr() != "" })

	user := fmt.Sprintf("hunted-%d", time.Now().UnixNano())
	sendSyslog(t, srv.CEFListenAddr(), fmt.Sprintf(
		`<165>1 2026-07-26T14:05:09Z fw01 sshd - AUTH [auth@32473 user="%s"] denied`, user))

	waitFor(t, func() bool {
		logs, err := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{
			FieldKey: "auth@32473.user", FieldValue: user, Limit: 10})
		return err == nil && len(logs) == 1
	})
}

// TestAnUnparseableLineIsCountedNotStored — a log ingest that quietly stores mangled lines is a blind spot
// that looks like coverage (D17).
func TestAnUnparseableLineIsCountedNotStored(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.RunCEFSyslog(ctx, "127.0.0.1:0") }()
	waitFor(t, func() bool { return srv.CEFListenAddr() != "" })

	before := srv.CEFDropped.Load()
	sendSyslog(t, srv.CEFListenAddr(), `<13>this is neither CEF nor RFC 5424`)
	waitFor(t, func() bool { return srv.CEFDropped.Load() > before })

	logs, err := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range logs {
		if l.Message == "this is neither CEF nor RFC 5424" {
			t.Error("an unparseable line was stored as a record")
		}
	}
}
