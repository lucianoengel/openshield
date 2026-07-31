// Package sysmon gives Sysmon's numeric event IDs their meaning (SIEM-17).
//
// Sysmon events already arrive: they are Windows events, so the WEF connector parses them and stores
// their EventData. What arrives is unusable at the point it matters. `Microsoft-Windows-Sysmon/1` is the
// single most important endpoint telemetry line Windows produces — a process was created — and stored as
// the string "1" it is huntable only by an analyst who has memorised Microsoft's table. In practice that
// means it is hunted by nobody, and the richest Windows source in the estate sits in the store being
// counted.
//
// So this is a NAMING layer, and deliberately nothing more:
//
//   - an event ID becomes an action an operator can search for and a rule can match on;
//   - Sysmon's own field names join the cross-vendor vocabulary (SIEM-13), so `Image` answers the same
//     question as a Linux exec path and `DestinationIp` the same question as CEF's `dst`.
//
// IT INTERPRETS NOTHING. Which process creation is suspicious is the policy's job and the detector's,
// exactly as it is for every other source — this package would be the wrong place to encode that, and a
// connector that decided what was bad would put detection logic where nobody looks for it.
//
// AND IT NEVER FILTERS. Sysmon's schema grows between versions, so a field this map does not know is
// still stored under its own name and still huntable. A mapping layer that dropped what it did not
// recognise would silently narrow the estate's best endpoint source every time Microsoft shipped a
// release.
package sysmon

import "strings"

// Provider is the Sysmon provider name as it appears in the Windows event's System block.
const Provider = "Microsoft-Windows-Sysmon"

// actions maps Sysmon's event IDs to the action names this product hunts on.
//
// The names are OURS, not Microsoft's: lower-case, underscored, and shaped like the actions the rest of
// the pipeline already uses, so a rule written against `process_create` reads the same whether the event
// came from Sysmon or from the Linux exec gate. Naming them after Microsoft's UI strings would make
// every cross-platform rule two rules.
var actions = map[string]string{
	"1":  "process_create",
	"2":  "file_create_time_changed", // the timestomping primitive
	"3":  "network_connect",
	"4":  "sysmon_state_changed",
	"5":  "process_terminate",
	"6":  "driver_load",
	"7":  "image_load",
	"8":  "create_remote_thread", // the classic injection primitive
	"9":  "raw_access_read",      // raw disk read, the credential-theft primitive
	"10": "process_access",
	"11": "file_create",
	"12": "registry_key_create_delete",
	"13": "registry_value_set",
	"14": "registry_key_rename",
	"15": "file_create_stream_hash",
	"16": "sysmon_config_changed",
	"17": "pipe_created",
	"18": "pipe_connected",
	"19": "wmi_filter",
	"20": "wmi_consumer",
	"21": "wmi_binding",
	"22": "dns_query",
	"23": "file_delete_archived",
	"24": "clipboard_change",
	"25": "process_tampering", // hollowing / herpaderping
	"26": "file_delete_logged",
	"27": "file_block_executable",
	"28": "file_block_shredding",
	"29": "file_executable_detected",
}

// IsSysmon reports whether a Windows event came from Sysmon.
//
// Prefix match, because deployments see the provider both bare and with a `-Operational` suffix or a
// GUID alongside it, and an exact comparison would silently treat those as ordinary Windows events —
// which is not a crash but a whole endpoint fleet quietly losing its naming.
func IsSysmon(provider string) bool {
	return strings.HasPrefix(strings.TrimSpace(provider), Provider)
}

// Action returns the action name for a Sysmon event ID.
//
// An UNKNOWN id keeps its number rather than becoming "unknown". Sysmon gains event IDs with every
// release, and mapping all of them to one label would collapse every new event type into a single
// bucket — a hunt for that bucket would return an unrelated mixture, and nobody would notice the map had
// fallen behind. A bare number is visibly a number.
func Action(eventID string) (string, bool) {
	a, ok := actions[strings.TrimSpace(eventID)]
	if !ok {
		return "", false
	}
	return a, true
}

// KnownIDs reports how many event IDs are mapped, so a test can assert the table has not been emptied by
// a bad edit — a map that silently became empty would name nothing and fail no test that only checked
// individual lookups.
func KnownIDs() int { return len(actions) }
