// Package fanotify is the observe front-end connector (Direction 2).
//
// It watches directories in fanotify NOTIFY mode and turns real file activity
// into Events. Probed facts bound what it does: fanotify PERMISSION mode
// (blocking) needs init-namespace CAP_SYS_ADMIN, and FID handle resolution needs
// CAP_DAC_READ_SEARCH — both unavailable in rootless podman. NOTIFY mode with a
// per-directory mark works UNPRIVILEGED, and the file path is simply
// watchedDir/name from the event, so no privileged handle resolution is needed.
//
// It produces Events (paths, never content — D29); classification stays in the
// worker. Blocking and recursive/FID watches are the privileged edge, deferred.
package fanotify

import (
	"encoding/binary"
	"path/filepath"
	"strings"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// info record type for a parent-dir handle + name (FAN_EVENT_INFO_TYPE_DFID_NAME).
const infoTypeDFIDName = 2

// fanotify masks we map (native little-endian on the platforms that ship, D9).
const (
	fanModify     = 0x00000002
	fanCloseWrite = 0x00000008
	fanCreate     = 0x00000100
)

const metaLen = 24 // sizeof(struct fanotify_event_metadata) on 64-bit

// ParseEvent decodes one fanotify event from raw, returning the produced Event,
// the number of bytes consumed (so a buffer of several events can be walked), and
// ok=false if the buffer does not hold a complete event.
//
// Pure over bytes — no kernel needed — so it is unit-tested against a fixed
// layout, and the live watch cross-checks it against the real kernel.
func ParseEvent(watchDir string, raw []byte) (ev *corev1.Event, consumed int, ok bool) {
	if len(raw) < metaLen {
		return nil, 0, false
	}
	eventLen := int(binary.LittleEndian.Uint32(raw[0:4]))
	if eventLen < metaLen || eventLen > len(raw) {
		return nil, 0, false
	}
	mask := binary.LittleEndian.Uint64(raw[8:16])
	name := parseDFIDName(raw[metaLen:eventLen])

	e := &corev1.Event{
		ConnectorId: "fanotify",
		Kind:        kindFromMask(mask),
	}
	if name != "" {
		e.EventId = "fan-" + name
		e.Target = &corev1.Event_Filesystem{Filesystem: &corev1.FilesystemSubject{
			Identity: &corev1.FilesystemSubject_ResolvedPath{
				ResolvedPath: filepath.Join(watchDir, name),
			}}}
	}
	return e, eventLen, true
}

// parseDFIDName finds the DFID_NAME info record and returns the filename.
func parseDFIDName(info []byte) string {
	off := 0
	for off+4 <= len(info) {
		typ := info[off]
		recLen := int(binary.LittleEndian.Uint16(info[off+2 : off+4]))
		if recLen < 4 || off+recLen > len(info) {
			break
		}
		if typ == infoTypeDFIDName {
			// infoHdr(4) + fsid(8) + file_handle{bytes u32, type i32, handle[bytes]} + name
			p := off + 4 + 8
			if p+8 > off+recLen {
				return ""
			}
			handleBytes := int(binary.LittleEndian.Uint32(info[p : p+4]))
			nameStart := p + 8 + handleBytes
			if nameStart > off+recLen {
				return ""
			}
			return strings.TrimRight(string(info[nameStart:off+recLen]), "\x00")
		}
		off += recLen
	}
	return ""
}

func kindFromMask(mask uint64) corev1.EventKind {
	switch {
	case mask&fanCreate != 0:
		return corev1.EventKind_EVENT_KIND_FILE_CREATED
	case mask&(fanModify|fanCloseWrite) != 0:
		return corev1.EventKind_EVENT_KIND_FILE_MODIFIED
	default:
		return corev1.EventKind_EVENT_KIND_UNSPECIFIED
	}
}
