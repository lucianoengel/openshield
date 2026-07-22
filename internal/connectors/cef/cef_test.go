package cef

import (
	"strings"
	"testing"
)

func TestParseCanonical(t *testing.T) {
	line := `CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232`
	m, err := Parse([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Version != "0" || m.Vendor != "Security" || m.Product != "threatmanager" ||
		m.DeviceVersion != "1.0" || m.SignatureID != "100" || m.Name != "worm successfully stopped" ||
		m.Severity != "10" {
		t.Fatalf("headers wrong: %+v", m)
	}
	if m.Extensions["src"] != "10.0.0.1" || m.Extensions["dst"] != "2.1.2.2" || m.Extensions["spt"] != "1232" {
		t.Fatalf("extension wrong: %v", m.Extensions)
	}
}

func TestSpacesInValueKeptWhole(t *testing.T) {
	line := `CEF:0|V|P|1|1|n|5|msg=worm stopped by rule 42 src=10.0.0.1`
	m, err := Parse([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if m.Extensions["msg"] != "worm stopped by rule 42" {
		t.Fatalf("msg value = %q, want the whole space-containing string", m.Extensions["msg"])
	}
	if m.Extensions["src"] != "10.0.0.1" {
		t.Fatalf("src = %q, want 10.0.0.1", m.Extensions["src"])
	}
}

func TestHeaderEscapedPipe(t *testing.T) {
	// A device version containing a literal pipe: 1\|2.
	line := `CEF:0|Acme\|Corp|Prod|1\|2|42|the name|3|k=v`
	m, err := Parse([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if m.Vendor != "Acme|Corp" {
		t.Fatalf("vendor = %q, want Acme|Corp (escaped pipe)", m.Vendor)
	}
	if m.DeviceVersion != "1|2" {
		t.Fatalf("device version = %q, want 1|2", m.DeviceVersion)
	}
	if m.SignatureID != "42" || m.Name != "the name" || m.Severity != "3" {
		t.Fatalf("later headers shifted by the escaped pipe: %+v", m)
	}
}

func TestValueEscapes(t *testing.T) {
	line := `CEF:0|V|P|1|1|n|5|expr=a\=b path=c\\d note=line1\nline2`
	m, err := Parse([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if m.Extensions["expr"] != "a=b" {
		t.Fatalf("expr = %q, want a=b (escaped =)", m.Extensions["expr"])
	}
	if m.Extensions["path"] != `c\d` {
		t.Fatalf("path = %q, want c\\d (escaped backslash)", m.Extensions["path"])
	}
	if m.Extensions["note"] != "line1\nline2" {
		t.Fatalf("note = %q, want line1<newline>line2", m.Extensions["note"])
	}
}

func TestRejections(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"no prefix":    "0|V|P|1|1|n|5|k=v",
		"five headers": "CEF:0|V|P|1|1",
		"oversized":    "CEF:" + strings.Repeat("A", maxLine),
	}
	for name, line := range cases {
		if _, err := Parse([]byte(line)); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}
