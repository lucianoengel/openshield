package controlplane_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// TestExternalLogStoreRoundTrip (SIEM-4): an inserted external log is found by a filtered search with
// its fields intact, and the result set is capped.
func TestExternalLogStoreRoundTrip(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	rec := controlplane.ExternalLog{
		SourceHost: "fw01", Vendor: "Acme", Product: "Firewall", SignatureID: "100",
		Name: "Worm blocked", Severity: "8", Message: "worm stopped by rule 42",
		Raw: "CEF:0|Acme|Firewall|1.2|100|Worm blocked|8|src=10.0.0.1",
	}
	if err := srv.InsertExternalLog(ctx, rec); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{Vendor: "Acme", Since: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("search returned %d rows, want 1", len(got))
	}
	if got[0].Product != "Firewall" || got[0].SignatureID != "100" || got[0].Name != "Worm blocked" || got[0].Message != "worm stopped by rule 42" {
		t.Fatalf("round-tripped record wrong: %+v", got[0])
	}
	// A different vendor does not match.
	other, _ := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{Vendor: "Nobody"})
	if len(other) != 0 {
		t.Fatalf("vendor filter leaked %d rows", len(other))
	}

	// The limit is capped: insert many, request an absurd limit, get at most the cap.
	for i := 0; i < 5; i++ {
		_ = srv.InsertExternalLog(ctx, controlplane.ExternalLog{Vendor: "Bulk", Severity: "3"})
	}
	capped, err := srv.SearchExternalLogs(ctx, controlplane.ExternalLogFilter{Vendor: "Bulk", Limit: 1_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) > 10_000 {
		t.Fatalf("search returned %d rows — the limit is not capped", len(capped))
	}
}

// TestCEFSyslogListenerEndToEnd (SIEM-4, real UDP + real PG): a CEF-over-syslog datagram sent to the
// running listener is parsed, persisted, and found by search; a non-CEF datagram is counted as dropped
// and the listener keeps serving.
func TestCEFSyslogListenerEndToEnd(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.RunCEFSyslog(ctx, "127.0.0.1:0") }()

	// Wait for the listener to bind and report its address.
	var addr string
	waitFor(t, func() bool { addr = srv.CEFListenAddr(); return addr != "" })

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// A CEF-over-syslog datagram: <PRI>timestamp host CEF:...
	sig := fmt.Sprintf("%d", time.Now().UnixNano()) // unique so search isolates this run
	cefDatagram := fmt.Sprintf(`<134>1 2026-07-22T10:00:00Z fw02 firewall - - - CEF:0|Acme|IDS|2.0|%s|Port scan|6|src=192.168.1.5`, sig)
	if _, err := conn.Write([]byte(cefDatagram)); err != nil {
		t.Fatal(err)
	}

	// It becomes searchable (by its unique signature id).
	waitFor(t, func() bool {
		rows, _ := srv.SearchExternalLogs(context.Background(), controlplane.ExternalLogFilter{Product: "IDS"})
		for _, r := range rows {
			if r.SignatureID == sig {
				return true
			}
		}
		return false
	})
	if srv.CEFIngested.Load() < 1 {
		t.Fatal("CEFIngested did not increment for a valid CEF datagram")
	}

	// A non-CEF datagram is dropped (counted), and the listener keeps serving.
	beforeDrop := srv.CEFDropped.Load()
	if _, err := conn.Write([]byte(`<134>1 2026-07-22T10:00:01Z host2 sshd - - - Accepted password for alice`)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return srv.CEFDropped.Load() > beforeDrop })

	// The listener still ingests a subsequent CEF datagram (it did not crash on the non-CEF one).
	sig2 := fmt.Sprintf("%d", time.Now().UnixNano())
	after := fmt.Sprintf(`<134>1 2026-07-22T10:00:02Z fw02 firewall - - - CEF:0|Acme|IDS|2.0|%s|Second event|6|`, sig2)
	if _, err := conn.Write([]byte(after)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		rows, _ := srv.SearchExternalLogs(context.Background(), controlplane.ExternalLogFilter{Product: "IDS"})
		for _, r := range rows {
			if r.SignatureID == sig2 {
				return true
			}
		}
		return false
	})
}
