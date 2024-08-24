//go:build linux

package journalx

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unsafe"
)

// This file holds the human-readable header dump, modelled on the output
// of `journalctl --header`. It is diagnostic only: nothing in the read
// path calls it, and it is the fastest way to find out why a file will
// not parse.
//
// It writes to an io.Writer rather than the log, because a library that
// logs takes a decision that belongs to the application.

// dumpHeader writes h as aligned key-value lines. Blank values mark
// fields journalctl prints that this reader does not compute: the disk
// usage needs a stat, the hash table fill levels need a walk of both
// tables, and rotate-suggested needs systemd's own heuristic.
func dumpHeader(w io.Writer, name string, h header) error {
	hashItemSize := uint64(unsafe.Sizeof(hashItem{}))

	lines := []struct {
		key   string
		value any
	}{
		{"File path", name},
		{"File ID", h.FileID},
		{"Machine ID", h.MachineID},
		{"Boot ID", h.TailEntryBootID},
		{"Sequential number ID", h.SeqnumID},
		{"State", stateString(h.State)},
		{"Compatible flags", strings.Join(compatibleFlagNames(h.CompatibleFlags), " ")},
		{"Incompatible flags", strings.Join(incompatibleFlagNames(h.IncompatibleFlags), " ")},
		{"Header size", h.HeaderSize},
		{"Arena size", h.ArenaSize},
		{"Data hash table size", h.DataHashTableSize / hashItemSize},
		{"Field hash table size", h.FieldHashTableSize / hashItemSize},
		{"Rotate suggested", ""},
		{"Head sequential number", h.HeadEntrySeqnum},
		{"Tail sequential number", h.TailEntrySeqnum},
		{"Head realtime timestamp", time.UnixMicro(int64(h.HeadEntryRealtime))},
		{"Tail realtime timestamp", time.UnixMicro(int64(h.TailEntryRealtime))},
		{"Tail monotonic timestamp", time.Duration(h.TailEntryMonotonic) * time.Microsecond},
		{"Objects", h.NObjects},
		{"Entry objects", h.NEntries},
		{"Data hash table fill", ""},
		{"Field hash table fill", ""},
		{"Disk usage", ""},
	}
	for _, l := range lines {
		if _, err := fmt.Fprintf(w, "%-24s %v\n", l.key+":", l.value); err != nil {
			return err
		}
	}
	return nil
}

func stateString(s uint8) string {
	switch s {
	case stateOffline:
		return "OFFLINE"
	case stateOnline:
		return "ONLINE"
	case stateArchived:
		return "ARCHIVED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

func compatibleFlagNames(flags uint32) []string {
	var names []string
	if flags&compatibleSealed != 0 {
		names = append(names, "SEALED")
	}
	if flags&compatibleTailEntryBootID != 0 {
		names = append(names, "TAIL_ENTRY_BOOT_ID")
	}
	if unknown := flags &^ (compatibleSealed | compatibleTailEntryBootID); unknown != 0 {
		names = append(names, fmt.Sprintf("%#x", unknown))
	}
	return names
}

func incompatibleFlagNames(flags uint32) []string {
	var names []string
	for _, f := range []struct {
		bit  uint32
		name string
	}{
		{incompatibleCompressedXZ, "COMPRESSED-XZ"},
		{incompatibleCompressedLZ4, "COMPRESSED-LZ4"},
		{incompatibleKeyedHash, "KEYED-HASH"},
		{incompatibleCompressedZSTD, "COMPRESSED-ZSTD"},
		{incompatibleCompact, "COMPACT"},
	} {
		if flags&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	known := incompatibleCompressedXZ | incompatibleCompressedLZ4 |
		incompatibleKeyedHash | incompatibleCompressedZSTD | incompatibleCompact
	if unknown := flags &^ known; unknown != 0 {
		names = append(names, fmt.Sprintf("%#x", unknown))
	}
	return names
}
