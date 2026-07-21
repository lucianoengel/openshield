package fanotify

import (
	"encoding/binary"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// A hand-built fanotify event buffer: metadata + a DFID_NAME info record.
func buildEvent(mask uint64, name string) []byte {
	// info record: infoHdr(4) + fsid(8) + fh{bytes u32, type i32, handle} + name
	handle := []byte{0xAA, 0xBB, 0xCC, 0xDD} // 4-byte opaque handle
	recBody := make([]byte, 8+8+len(handle)+len(name)+1)
	// fsid (8 bytes) left zero
	binary.LittleEndian.PutUint32(recBody[8:], uint32(len(handle))) // handle bytes
	binary.LittleEndian.PutUint32(recBody[12:], 1)                  // handle type
	copy(recBody[16:], handle)
	copy(recBody[16+len(handle):], name)
	recLen := 4 + len(recBody)
	rec := make([]byte, recLen)
	rec[0] = infoTypeDFIDName
	binary.LittleEndian.PutUint16(rec[2:], uint16(recLen))
	copy(rec[4:], recBody)

	eventLen := metaLen + recLen
	buf := make([]byte, eventLen)
	binary.LittleEndian.PutUint32(buf[0:], uint32(eventLen))
	buf[4] = 3 // version
	binary.LittleEndian.PutUint16(buf[6:], metaLen)
	binary.LittleEndian.PutUint64(buf[8:], mask)
	copy(buf[metaLen:], rec)
	return buf
}

func TestParseEvent(t *testing.T) {
	buf := buildEvent(fanCloseWrite, "leak.csv")
	ev, consumed, ok := ParseEvent("/home/alice", buf)
	if !ok {
		t.Fatal("parse returned ok=false on a valid buffer")
	}
	if consumed != len(buf) {
		t.Errorf("consumed = %d, want %d", consumed, len(buf))
	}
	if got := ev.GetFilesystem().GetResolvedPath(); got != "/home/alice/leak.csv" {
		t.Errorf("path = %q, want /home/alice/leak.csv", got)
	}
	if ev.GetKind() != corev1.EventKind_EVENT_KIND_FILE_MODIFIED {
		t.Errorf("kind = %v, want FILE_MODIFIED for CLOSE_WRITE", ev.GetKind())
	}
	// CREATE mask → FILE_CREATED.
	cev, _, _ := ParseEvent("/d", buildEvent(fanCreate, "new.txt"))
	if cev.GetKind() != corev1.EventKind_EVENT_KIND_FILE_CREATED {
		t.Errorf("kind = %v, want FILE_CREATED for CREATE", cev.GetKind())
	}
	// A truncated buffer → ok=false.
	if _, _, ok := ParseEvent("/d", buf[:10]); ok {
		t.Error("a truncated buffer parsed as ok")
	}
}
