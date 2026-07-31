package sysmon_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/connectors/sysmon"
)

// SIEM-17 — SYSMON EVENT NAMING.
//
// Sysmon events already arrive; the WEF connector parses them and stores their EventData. What arrives
// is unusable at the point it matters. `Microsoft-Windows-Sysmon/1` is the single most important
// endpoint line Windows produces — a process was created — and stored as the string "1" it is huntable
// only by an analyst who has memorised Microsoft's table. In practice that means by nobody, and the
// richest Windows source in the estate sits in the store being counted.

// THE HEADLINE: the event IDs an investigation actually pivots on have names.
func TestTheEventIDsAnInvestigationPivotsOnAreNamed(t *testing.T) {
	for id, want := range map[string]string{
		"1":  "process_create",
		"3":  "network_connect",
		"7":  "image_load",
		"8":  "create_remote_thread", // injection
		"11": "file_create",
		"13": "registry_value_set",
		"22": "dns_query",
		"25": "process_tampering", // hollowing / herpaderping
	} {
		got, ok := sysmon.Action(id)
		if !ok {
			t.Errorf("event ID %s has no name — stored as %q it is huntable only by someone who has "+
				"memorised Microsoft's table", id, id)
			continue
		}
		if got != want {
			t.Errorf("event ID %s = %q, want %q", id, got, want)
		}
	}
}

// AN UNKNOWN ID KEEPS ITS NUMBER, and does not become "unknown".
//
// Sysmon gains event IDs with every release. Mapping all of them to one label collapses every new type
// into a single bucket: a hunt for that bucket returns an unrelated mixture, and nobody notices the map
// has fallen behind. A bare number is visibly a number.
//
// Mutation (return a constant like "unknown" with ok=true for an unmapped id): the caller stops being
// able to tell an unmapped event from a named one → FAIL.
func TestAnUnknownEventIDIsNotGivenAName(t *testing.T) {
	for _, id := range []string{"999", "", "not-a-number", "0"} {
		if got, ok := sysmon.Action(id); ok {
			t.Fatalf("event ID %q was named %q — Sysmon gains IDs with every release, and labelling "+
				"every new one the same way collapses them into a bucket a hunt returns an unrelated "+
				"mixture from, with nobody noticing the map has fallen behind", id, got)
		}
	}
}

// THE PROVIDER IS MATCHED BY PREFIX.
//
// Deployments see the provider bare, with an `-Operational` suffix, and alongside a GUID. An exact
// comparison treats those as ordinary Windows events — not a crash, but a whole endpoint fleet quietly
// losing its naming.
//
// Mutation (compare with ==): the suffixed provider stops being recognised → FAIL.
func TestTheProviderIsMatchedByPrefix(t *testing.T) {
	for _, p := range []string{
		"Microsoft-Windows-Sysmon",
		"Microsoft-Windows-Sysmon/Operational",
		"  Microsoft-Windows-Sysmon  ",
	} {
		if !sysmon.IsSysmon(p) {
			t.Errorf("provider %q was not recognised as Sysmon — an exact match loses a whole endpoint "+
				"fleet's naming without failing anything", p)
		}
	}
	for _, p := range []string{
		"Microsoft-Windows-Security-Auditing",
		"Sysmon",
		"",
	} {
		if sysmon.IsSysmon(p) {
			t.Errorf("provider %q was treated as Sysmon — the Security channel and the endpoint "+
				"telemetry answer different questions and must stay separable", p)
		}
	}
}

// THE TABLE IS NOT EMPTY. A map emptied by a bad edit would name nothing and fail no test that only
// checked individual lookups — every one of those would report "no name" and be indistinguishable from
// an id that was never mapped.
func TestTheActionTableIsPopulated(t *testing.T) {
	if n := sysmon.KnownIDs(); n < 20 {
		t.Fatalf("only %d event IDs are mapped; Sysmon's core set is larger, and a table that shrank "+
			"silently would name nothing while every individual lookup failed the same way an "+
			"unmapped id does", n)
	}
}
