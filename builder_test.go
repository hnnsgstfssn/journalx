//go:build linux

package journalx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"unsafe"

	"github.com/klauspost/compress/zstd"
)

// This file writes systemd journal files.
//
// It exists because the only other way to test a reader of this format
// is a machine running systemd with logs in it, which rules out a
// container, CI, and a laptop that is not Linux. The layout written here
// is the subset of the format the reader walks: a header, data objects,
// entry objects, and the entry array chain that orders them. Hash tables
// are sized in the header but never populated, because the reader never
// consults them.
//
// Everything is little-endian regardless of host, matching the le64_t
// types in systemd's journal-def.h.

const (
	// baseRealtime is the timestamp entries count up from, fixed so the
	// golden files are byte-reproducible. 2023-11-14T22:13:20Z.
	baseRealtime = uint64(1700000000_000000)

	// entryInterval is how far apart consecutive entries are placed, one
	// second, which is coarse enough to read in a failure message.
	entryInterval = uint64(1_000_000)
)

// align8 rounds up to the 8-byte boundary objects sit on in the arena.
func align8(n uint64) uint64 {
	return (n + 7) &^ 7
}

// builder assembles a journal file in memory and can then keep
// appending to it on disk, patching the header and the entry array in
// place the way systemd does. That matters for the growth test: an
// append must add bytes at the end and modify bytes in the middle, not
// rewrite the file, or it would exercise reopening rather than remapping.
type builder struct {
	t *testing.T

	compact bool
	zstd    bool

	// arena holds every object written so far. Offsets in the file are
	// headerSize plus the offset into arena.
	arena []byte

	// entryOffsets are file offsets of the entry objects, in order.
	entryOffsets []uint64

	// arrayCap is how many slots each entry array holds. Small values
	// force the reader onto the NextEntryArrayOffset path.
	arrayCap int

	// arrays are file offsets of the entry array objects, in order.
	arrays []uint64

	// slotsUsed counts entries recorded in the last array.
	slotsUsed int

	seqnum   uint64
	realtime uint64

	// firstSeqnum is the sequence number of the first entry, recorded so
	// the header can advertise the right head. It differs from one when
	// the file represents a continuation of a rotated journal.
	firstSeqnum uint64

	// seqnumID is the byte the 16-byte sequence ID is filled with. Two
	// builders with different values model two unrelated journals, whose
	// sequence numbers are not comparable and which must therefore be
	// merged by wall clock.
	seqnumID byte

	// file is set once written to disk, so appends can patch in place.
	file *os.File
}

// builderOption configures a builder.
type builderOption func(*builder)

// withCompact writes 32-bit object offsets and the compact data object
// layout, which is what systemd v252 and later produce by default.
func withCompact() builderOption { return func(b *builder) { b.compact = true } }

// withZSTD compresses every field payload, which is what systemd does
// once a payload exceeds its compression threshold.
func withZSTD() builderOption { return func(b *builder) { b.zstd = true } }

// withArrayCap sets how many entries each entry array holds.
func withArrayCap(n int) builderOption { return func(b *builder) { b.arrayCap = n } }

// withSeqnumID sets the journal's sequence ID. Files sharing an ID are
// one journal and its archives; files with different IDs are unrelated
// journals, such as the system journal and a user journal.
func withSeqnumID(v byte) builderOption { return func(b *builder) { b.seqnumID = v } }

// withStart sets the sequence number and timestamp the first entry
// follows on from, which is how a file that continues a rotated journal
// is described.
func withStart(seqnum, realtimeUsec uint64) builderOption {
	return func(b *builder) {
		b.seqnum = seqnum
		b.realtime = realtimeUsec
	}
}

func newBuilder(t *testing.T, opts ...builderOption) *builder {
	t.Helper()
	b := &builder{
		t:        t,
		arrayCap: 64,
		realtime: baseRealtime,
		seqnumID: 0x44,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// fields is an ordered list of NAME=value pairs. A slice rather than a
// map because order must be reproducible for golden files, and because
// a name may legally repeat within one entry.
type fields [][2]string

// addEntry appends one entry with the given fields. It must be called
// before write.
func (b *builder) addEntry(f fields) {
	b.t.Helper()
	if b.file != nil {
		b.t.Fatal("addEntry after write: use appendEntry")
	}
	b.appendEntryTo(headerSize, &b.arena, f)
}

// appendEntryTo writes the data objects and the entry object for one
// entry into dst.
//
// base is the file offset that dst will be written at. It is a parameter
// rather than derived from the arena because appendEntry builds the new
// objects in a separate buffer and writes them at the end of an existing
// file: offsets computed against an empty buffer would point at the
// start of the arena instead.
func (b *builder) appendEntryTo(base uint64, dst *[]byte, f fields) {
	b.t.Helper()

	dataOffsets := make([]uint64, len(f))
	for i, kv := range f {
		dataOffsets[i] = b.writeDataObject(base, dst, kv[0]+"="+kv[1])
	}

	b.seqnum++
	if b.firstSeqnum == 0 {
		b.firstSeqnum = b.seqnum
	}
	b.realtime += entryInterval // one second per entry, so ordering is visible
	entryOffset := b.writeEntryObject(base, dst, dataOffsets)
	b.entryOffsets = append(b.entryOffsets, entryOffset)
}

// offsetOf returns the file offset an object placed at the end of dst
// would have, given that dst itself starts at base.
func (b *builder) offsetOf(base uint64, dst *[]byte) uint64 {
	return base + uint64(len(*dst))
}

// writeDataObject appends a data object holding payload and returns its
// file offset.
func (b *builder) writeDataObject(base uint64, dst *[]byte, payload string) uint64 {
	b.t.Helper()
	offset := b.offsetOf(base, dst)

	body := []byte(payload)
	var flags uint8
	if b.zstd {
		body = compressZSTD(b.t, body)
		flags = objectCompressedZSTD
	}

	var o dataObject
	fixed := uint64(unsafe.Sizeof(o.Fields))
	if b.compact {
		fixed += uint64(unsafe.Sizeof(o.CompactFields))
	}
	size := uint64(unsafe.Sizeof(objectHeader{})) + fixed + uint64(len(body))

	var buf bytes.Buffer
	writeObjectHeader(&buf, objectData, flags, size)
	buf.Write(make([]byte, unsafe.Sizeof(o.Fields))) // hash and chain offsets: unread
	if b.compact {
		buf.Write(make([]byte, unsafe.Sizeof(o.CompactFields)))
	}
	buf.Write(body)

	b.appendAligned(dst, buf.Bytes())
	return offset
}

// writeEntryObject appends an entry object referencing dataOffsets and
// returns its file offset.
func (b *builder) writeEntryObject(base uint64, dst *[]byte, dataOffsets []uint64) uint64 {
	b.t.Helper()
	offset := b.offsetOf(base, dst)

	itemSize := uint64(unsafe.Sizeof(entryItem{}))
	if b.compact {
		itemSize = uint64(unsafe.Sizeof(entryItemCompact{}))
	}
	fixed := uint64(unsafe.Sizeof(entryObject{}.Fields))
	size := uint64(unsafe.Sizeof(objectHeader{})) + fixed + uint64(len(dataOffsets))*itemSize

	var buf bytes.Buffer
	writeObjectHeader(&buf, objectEntry, 0, size)
	writeU64(&buf, b.seqnum)
	writeU64(&buf, b.realtime)
	writeU64(&buf, b.realtime)  // monotonic: same value, unread by the reader
	buf.Write(make([]byte, 16)) // boot ID
	writeU64(&buf, 0)           // xor hash
	for _, d := range dataOffsets {
		if b.compact {
			writeU32(&buf, uint32(d))
			continue
		}
		writeU64(&buf, d)
		writeU64(&buf, 0) // per-item hash: unread
	}

	b.appendAligned(dst, buf.Bytes())
	return offset
}

// writeEntryArrays lays out the entry array chain over the entries added
// so far and returns the offset of its head.
//
// Arrays are written after all entries so that appendEntry can fill a
// trailing slot in place. Each array holds arrayCap slots; unused slots
// stay zero, which is how the reader knows an entry has not arrived yet.
func (b *builder) writeEntryArrays() uint64 {
	b.t.Helper()

	itemSize := uint64(8)
	if b.compact {
		itemSize = 4
	}
	fixed := uint64(unsafe.Sizeof(entryArrayObject{}.Fields))
	size := uint64(unsafe.Sizeof(objectHeader{})) + fixed + uint64(b.arrayCap)*itemSize

	// Chunk the entries into arrays, then link them. The offsets have to
	// be known before the links can be written, so reserve first.
	nArrays := max(1, (len(b.entryOffsets)+b.arrayCap-1)/b.arrayCap)
	for range nArrays {
		b.arrays = append(b.arrays, b.offsetOf(headerSize, &b.arena))
		b.appendAligned(&b.arena, make([]byte, size))
	}

	for i, arrayOffset := range b.arrays {
		var buf bytes.Buffer
		writeObjectHeader(&buf, objectEntryArray, 0, size)
		next := uint64(0)
		if i+1 < len(b.arrays) {
			next = b.arrays[i+1]
		}
		writeU64(&buf, next)

		for slot := range b.arrayCap {
			entry := i*b.arrayCap + slot
			offset := uint64(0)
			if entry < len(b.entryOffsets) {
				offset = b.entryOffsets[entry]
			}
			if b.compact {
				writeU32(&buf, uint32(offset))
				continue
			}
			writeU64(&buf, offset)
		}

		copy(b.arena[arrayOffset-headerSize:], buf.Bytes())
	}

	b.slotsUsed = len(b.entryOffsets) - (nArrays-1)*b.arrayCap
	return b.arrays[0]
}

// appendAligned appends obj to dst and pads to the next 8-byte boundary.
func (b *builder) appendAligned(dst *[]byte, obj []byte) {
	*dst = append(*dst, obj...)
	*dst = append(*dst, make([]byte, align8(uint64(len(obj)))-uint64(len(obj)))...)
}

// bytes returns the complete journal file.
func (b *builder) bytes() []byte {
	b.t.Helper()

	arrayOffset := b.writeEntryArrays()

	var out bytes.Buffer
	out.Write(b.headerBytes(arrayOffset))
	out.Write(b.arena)
	return out.Bytes()
}

// headerBytes serialises the file header.
func (b *builder) headerBytes(arrayOffset uint64) []byte {
	var incompatible uint32
	if b.compact {
		incompatible |= incompatibleCompact
	}
	if b.zstd {
		incompatible |= incompatibleCompressedZSTD
	}

	head := uint64(0)
	tail := uint64(0)
	if len(b.entryOffsets) > 0 {
		head = b.firstSeqnum
		tail = b.seqnum
	}

	var buf bytes.Buffer
	buf.WriteString(journalSignature)
	writeU32(&buf, compatibleTailEntryBootID)
	writeU32(&buf, incompatible)
	buf.WriteByte(stateOnline)
	buf.Write(make([]byte, 7)) // reserved

	// Fixed IDs so golden files are byte-reproducible.
	buf.Write(bytes.Repeat([]byte{0x11}, 16))       // file ID
	buf.Write(bytes.Repeat([]byte{0x22}, 16))       // machine ID
	buf.Write(bytes.Repeat([]byte{0x33}, 16))       // tail entry boot ID
	buf.Write(bytes.Repeat([]byte{b.seqnumID}, 16)) // seqnum ID

	hashTableSize := 64 * uint64(unsafe.Sizeof(hashItem{}))
	writeU64(&buf, headerSize)                  // header size
	writeU64(&buf, uint64(len(b.arena)))        // arena size
	writeU64(&buf, 0)                           // data hash table offset
	writeU64(&buf, hashTableSize)               // data hash table size
	writeU64(&buf, 0)                           // field hash table offset
	writeU64(&buf, hashTableSize)               // field hash table size
	writeU64(&buf, headerSize)                  // tail object offset
	writeU64(&buf, uint64(len(b.entryOffsets))) // n objects, approximated
	writeU64(&buf, uint64(len(b.entryOffsets))) // n entries
	writeU64(&buf, tail)                        // tail entry seqnum
	writeU64(&buf, head)                        // head entry seqnum
	writeU64(&buf, arrayOffset)                 // entry array offset
	writeU64(&buf, baseRealtime+entryInterval)  // head entry realtime
	writeU64(&buf, b.realtime)                  // tail entry realtime
	writeU64(&buf, b.realtime)                  // tail entry monotonic

	if uint64(buf.Len()) != headerSize {
		b.t.Fatalf("header is %d bytes, want %d: the struct and the writer disagree",
			buf.Len(), headerSize)
	}
	return buf.Bytes()
}

// write puts the journal at path and keeps the file open so appendEntry
// can extend it.
func (b *builder) write(path string) {
	b.t.Helper()
	if err := os.WriteFile(path, b.bytes(), 0o600); err != nil {
		b.t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() {
		if err := f.Close(); err != nil {
			b.t.Errorf("close builder file: %v", err)
		}
	})
	b.file = f
}

// appendEntry adds an entry to a journal already on disk, the way
// systemd does: the new objects go on the end, the entry's offset goes
// into the next free slot of the last entry array, and the header's tail
// counters move.
//
// It fails if the last array is full rather than growing the chain,
// because a test that silently stopped exercising the append path would
// be worse than one that stops.
func (b *builder) appendEntry(f fields) {
	b.t.Helper()
	if b.file == nil {
		b.t.Fatal("appendEntry before write")
	}
	if b.slotsUsed >= b.arrayCap {
		b.t.Fatalf("entry array full (%d slots): raise withArrayCap", b.arrayCap)
	}

	stat, err := b.file.Stat()
	if err != nil {
		b.t.Fatal(err)
	}

	// Objects are appended at the current end of file, so the arena the
	// offsets are computed against has to match what is on disk.
	b.arena = b.arena[:uint64(stat.Size())-headerSize]
	var appended []byte
	before := len(b.entryOffsets)
	b.appendEntryTo(uint64(stat.Size()), &appended, f)

	if _, err := b.file.WriteAt(appended, stat.Size()); err != nil {
		b.t.Fatal(err)
	}
	b.arena = append(b.arena, appended...)

	// Fill the array slot. Doing this after the entry object is on disk
	// matters: a reader that saw the slot first would follow an offset
	// into bytes that do not exist yet.
	lastArray := b.arrays[len(b.arrays)-1]
	itemSize := uint64(8)
	if b.compact {
		itemSize = 4
	}
	slotOffset := lastArray +
		uint64(unsafe.Sizeof(objectHeader{})) +
		uint64(unsafe.Sizeof(entryArrayObject{}.Fields)) +
		uint64(b.slotsUsed)*itemSize

	var slot bytes.Buffer
	if b.compact {
		writeU32(&slot, uint32(b.entryOffsets[before]))
	} else {
		writeU64(&slot, b.entryOffsets[before])
	}
	if _, err := b.file.WriteAt(slot.Bytes(), int64(slotOffset)); err != nil {
		b.t.Fatal(err)
	}
	b.slotsUsed++

	// Finally the header, so the tail sequence number never advertises
	// an entry that is not readable yet.
	if _, err := b.file.WriteAt(b.headerBytes(b.arrays[0]), 0); err != nil {
		b.t.Fatal(err)
	}
	if err := b.file.Sync(); err != nil {
		b.t.Fatal(err)
	}
}

// --- serialisation helpers ---------------------------------------------------

func writeObjectHeader(buf *bytes.Buffer, typ, flags uint8, size uint64) {
	buf.WriteByte(typ)
	buf.WriteByte(flags)
	buf.Write(make([]byte, 6)) // reserved
	writeU64(buf, size)
}

func writeU64(buf *bytes.Buffer, v uint64) {
	binary.Write(buf, binary.LittleEndian, v) //nolint:errcheck
}

func writeU32(buf *bytes.Buffer, v uint32) {
	binary.Write(buf, binary.LittleEndian, v) //nolint:errcheck
}

func writeZeros(buf *bytes.Buffer, n int) {
	buf.Write(make([]byte, n))
}

func compressZSTD(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	// Deterministic settings so golden files do not churn when the
	// compressor's defaults change.
	zw, err := zstd.NewWriter(&out,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(1<<17),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// describe renders a builder's configuration for test names and for the
// generator's manifest.
func (b *builder) describe() string {
	return fmt.Sprintf("compact=%v zstd=%v arrayCap=%d entries=%d",
		b.compact, b.zstd, b.arrayCap, len(b.entryOffsets))
}
