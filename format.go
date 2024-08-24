//go:build linux

package journalx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"unsafe"

	"github.com/klauspost/compress/zstd"
)

// Error is the type of the errors this package returns by identity.
type Error string

func (e Error) Error() string { return string(e) }

const (
	// ErrUnsupportedFlags reports a journal file using an on-disk
	// feature this reader cannot parse, such as XZ or LZ4 payload
	// compression.
	ErrUnsupportedFlags Error = "journalx: unsupported incompatible flags"

	// ErrCorrupt reports an object whose header cannot describe a
	// well-formed object, for example a size smaller than the object's
	// own fixed fields.
	ErrCorrupt Error = "journalx: corrupt journal object"
)

// journalSignature is the 8 bytes every journal file starts with. A file
// that does not begin with it is not a journal, and saying so is much
// more useful than the parse failure that follows otherwise.
const journalSignature = "LPKSHHRH"

// headerSize is the size of the header struct this reader knows about.
// A file written by a newer systemd may report a larger HeaderSize,
// because fields have been appended over time; the prefix this reader
// parses is stable.
const headerSize = uint64(unsafe.Sizeof(header{}))

// Object types, from systemd's ObjectType enum. Only objectData,
// objectEntry and objectEntryArray are needed to walk the entry chain;
// the rest are here because the numbering is only legible as a whole.
const (
	objectUnused uint8 = iota
	objectData
	objectField
	objectEntry
	objectDataHashTable
	objectFieldHashTable
	objectEntryArray
	objectTag
	objectTypeMax
)

// Compatible header flags. A reader may ignore these and still parse the
// file, which is what distinguishes them from the incompatible set. Spec
// names are HEADER_COMPATIBLE_SEALED and
// HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID.
const (
	compatibleSealed          uint32 = 1 << 0
	compatibleTailEntryBootID uint32 = 1 << 1
)

// Header State values. Spec names are STATE_OFFLINE, STATE_ONLINE and
// STATE_ARCHIVED. An online file is one systemd currently has open for
// writing, which is the normal case for the file this reader follows.
const (
	stateOffline uint8 = iota
	stateOnline
	stateArchived
	stateMax
)

// Incompatible header flags. A reader that does not understand one of
// these cannot read the file at all, which is what distinguishes them
// from the compatible flags.
const (
	incompatibleCompressedXZ   uint32 = 1 << 0
	incompatibleCompressedLZ4  uint32 = 1 << 1
	incompatibleKeyedHash      uint32 = 1 << 2
	incompatibleCompressedZSTD uint32 = 1 << 3
	incompatibleCompact        uint32 = 1 << 4
)

// Per-object flags. The compression bits occupy the same positions as
// the corresponding incompatible header flags but apply to one payload.
const (
	objectCompressedXZ   uint8 = 1 << 0
	objectCompressedLZ4  uint8 = 1 << 1
	objectCompressedZSTD uint8 = 1 << 2
)

// supportedIncompatibleFlags enumerates the incompatible features this
// implementation parses correctly. Keyed hashing only affects hash table
// lookup, which this reader does not do, and compact mode is handled by
// the object readers, so both are safe to accept.
const supportedIncompatibleFlags = incompatibleCompressedZSTD |
	incompatibleKeyedHash |
	incompatibleCompact

// validateIncompatibleFlags rejects a file this reader would otherwise
// misparse. Naming the unsupported feature matters because the fix is
// different for each: XZ and LZ4 need a decompressor, an unknown bit
// needs a newer reader.
func validateIncompatibleFlags(flags uint32) error {
	switch {
	case flags&incompatibleCompressedXZ != 0:
		return fmt.Errorf("%w: XZ compression", ErrUnsupportedFlags)
	case flags&incompatibleCompressedLZ4 != 0:
		return fmt.Errorf("%w: LZ4 compression", ErrUnsupportedFlags)
	}
	if unknown := flags &^ supportedIncompatibleFlags; unknown != 0 {
		return fmt.Errorf("%w: %#x", ErrUnsupportedFlags, unknown)
	}
	return nil
}

// sdID128 is systemd's 128-bit ID, used for machine, boot and file IDs.
type sdID128 struct {
	Bytes [16]uint8
}

func (id sdID128) String() string {
	return hex.EncodeToString(id.Bytes[:])
}

// header is the journal file header. Field order and width are fixed by
// the on-disk format, so this struct is read with binary.Read and must
// not be reordered.
//
// systemd has appended fields to this header over time (NData and
// NFields in v187, NTags and NEntryArrays in v189, the hash chain depths
// in v246, the tail entry array fields in v252, TailEntryOffset in
// v254). None are read here, and HeaderSize records where the header
// this reader knows about ends, so a newer file stays readable.
type header struct {
	Signature         [8]uint8 // "LPKSHHRH"
	CompatibleFlags   uint32
	IncompatibleFlags uint32
	State             uint8
	Reserved          [7]uint8

	FileID          sdID128
	MachineID       sdID128
	TailEntryBootID sdID128
	SeqnumID        sdID128

	HeaderSize           uint64
	ArenaSize            uint64
	DataHashTableOffset  uint64
	DataHashTableSize    uint64
	FieldHashTableOffset uint64
	FieldHashTableSize   uint64
	TailObjectOffset     uint64
	NObjects             uint64
	NEntries             uint64
	TailEntrySeqnum      uint64
	HeadEntrySeqnum      uint64
	EntryArrayOffset     uint64
	HeadEntryRealtime    uint64
	TailEntryRealtime    uint64
	TailEntryMonotonic   uint64
}

// compact reports whether object offsets in this file are 32-bit.
func (h header) compact() bool {
	return h.IncompatibleFlags&incompatibleCompact != 0
}

// objectHeader precedes every object in the arena. Size counts the
// header itself plus the payload, before padding to the next 8-byte
// boundary.
type objectHeader struct {
	Type     uint8
	Flags    uint8
	Reserved [6]uint8
	Size     uint64
}

// dataObject holds one NAME=value field shared by every entry that
// references it.
type dataObject struct {
	// Payload is the raw NAME=value bytes, decompressed if needed. It
	// is not necessarily valid UTF-8: the journal stores arbitrary
	// binary field values, which is why the export format has a
	// length-prefixed form for them.
	Payload []byte

	// CompactFields is present only in compact files and records where
	// the field's entry array tail is, which this reader does not use.
	CompactFields struct {
		TailEntryArrayOffset   uint32
		TailEntryArrayNEntries uint32
	}

	Fields struct {
		Hash             uint64
		NextHashOffset   uint64
		NextFieldOffset  uint64
		EntryOffset      uint64
		EntryArrayOffset uint64
		NEntries         uint64
	}
}

// fieldObjectItem is a single byte of a field object's payload.
type fieldObjectItem byte

// fieldObject holds a field name and heads the chain of data objects
// that have ever carried a value for it. This reader walks entries
// rather than fields, so it never reads one.
type fieldObject struct {
	Payload []byte
	Fields  struct {
		Hash           uint64
		NextHashOffset uint64
		HeadDataOffset uint64
	}
}

// hashItem is one bucket of a data or field hash table. Only the table
// sizes are used here, to report bucket counts.
type hashItem struct {
	HeadHashOffset uint64
	TailHashOffset uint64
}

// hashTableObject is the data or field hash table, used to find an
// existing field value without a scan. Unused: this reader streams the
// entry chain and never looks a value up by hash.
type hashTableObject struct {
	Items []hashItem
}

// tagLength is the width of a tagObject's HMAC, SHA-256.
const tagLength = 256 / 8

// tagObject seals a range of the journal with an HMAC when Forward
// Secure Sealing is enabled. Verifying it needs the sealing key, which
// this reader has no way to obtain, so a sealed file is read without
// checking its tags.
type tagObject struct {
	Seqnum uint64
	Epoch  uint64
	Tag    [tagLength]uint8
}

// entryItem points at the data object holding one field of an entry.
type entryItem struct {
	ObjectOffset uint64
	Hash         uint64
}

// entryItemCompact is the compact-mode form of entryItem: a 32-bit
// offset and no hash.
type entryItemCompact struct {
	ObjectOffset uint32
}

// entryObject is one log entry: a timestamped set of references to data
// objects.
type entryObject struct {
	Items  []entryItem
	Fields struct {
		Seqnum    uint64
		Realtime  uint64
		Monotonic uint64
		BootID    sdID128
		XorHash   uint64
	}
}

// entryArrayObject is a chunk of the singly linked list of entry
// offsets that gives the journal its chronological order. Trailing
// items are zero until they are written, so a zero offset means "not
// yet" rather than "end".
type entryArrayObject struct {
	Items  []uint64
	Fields struct {
		NextEntryArrayOffset uint64
	}
}

// itemCount returns how many items of itemSize fit in an object whose
// header reports oh.Size, after its fixed fields.
//
// The size check is not defensive programming for its own sake. The
// subtraction is unsigned, so an object header reporting a size smaller
// than its own fixed part wraps around to a value near 2^64, and the
// caller then asks make for that many items. A journal file is mapped
// while systemd is still appending to it, so a header that arrives
// before its payload is ordinary, not hypothetical.
func itemCount(oh objectHeader, fixedSize, itemSize uint64) (uint64, error) {
	overhead := uint64(unsafe.Sizeof(oh)) + fixedSize
	if oh.Size < overhead {
		return 0, fmt.Errorf("%w: type %d size %d below %d bytes of fixed fields",
			ErrCorrupt, oh.Type, oh.Size, overhead)
	}
	return (oh.Size - overhead) / itemSize, nil
}

// readObject reads the object at r's current position.
//
// Two size checks happen before any object body is parsed, and they are
// deliberately classified differently.
//
// An object smaller than its own header cannot exist, so that is
// corruption. An object whose body extends past the end of the mapping
// is reported as an unexpected EOF instead, because that is what the
// tail of a file systemd is still appending to looks like, and waiting
// for the next change is also the right response to a writer that
// stopped part-way through an object. The consequence of a genuinely
// wrong size is therefore a stream that stops advancing, rather than a
// process that allocates exabytes.
//
// That second check is also what bounds every allocation below: no
// object can ask for more memory than the file has bytes.
func readObject(h header, r *bytes.Reader) (any, error) {
	var oh objectHeader
	if err := read(r, &oh); err != nil {
		return nil, err
	}

	headerLen := uint64(unsafe.Sizeof(oh))
	if oh.Size < headerLen {
		return nil, fmt.Errorf("%w: type %d size %d below the %d byte object header",
			ErrCorrupt, oh.Type, oh.Size, headerLen)
	}
	if body := oh.Size - headerLen; body > uint64(r.Len()) {
		return nil, fmt.Errorf("object type %d wants %d bytes of body, %d available: %w",
			oh.Type, body, r.Len(), io.ErrUnexpectedEOF)
	}

	switch oh.Type {
	case objectData:
		return readDataObject(h, r, oh)
	case objectEntry:
		return readEntryObject(h, r, oh)
	case objectEntryArray:
		return readEntryArrayObject(h, r, oh)
	default:
		return nil, fmt.Errorf("%w: unknown object type %d", ErrCorrupt, oh.Type)
	}
}

func readDataObject(h header, r *bytes.Reader, oh objectHeader) (*dataObject, error) {
	var o dataObject

	fixedSize := uint64(unsafe.Sizeof(o.Fields))
	if h.compact() {
		fixedSize += uint64(unsafe.Sizeof(o.CompactFields))
	}
	n, err := itemCount(oh, fixedSize, 1)
	if err != nil {
		return nil, err
	}

	if err := read(r, &o.Fields); err != nil {
		return nil, err
	}
	if h.compact() {
		if err := read(r, &o.CompactFields); err != nil {
			return nil, err
		}
	}
	o.Payload = make([]byte, n)
	if err := read(r, o.Payload); err != nil {
		return nil, err
	}

	switch {
	case oh.Flags&objectCompressedZSTD != 0:
		payload, err := decompressZSTD(o.Payload)
		if err != nil {
			return nil, err
		}
		o.Payload = payload
	case oh.Flags&objectCompressedXZ != 0:
		return nil, fmt.Errorf("%w: XZ compressed data object", ErrUnsupportedFlags)
	case oh.Flags&objectCompressedLZ4 != 0:
		return nil, fmt.Errorf("%w: LZ4 compressed data object", ErrUnsupportedFlags)
	}
	return &o, nil
}

func readEntryObject(h header, r *bytes.Reader, oh objectHeader) (*entryObject, error) {
	var o entryObject

	fixedSize := uint64(unsafe.Sizeof(o.Fields))
	itemSize := uint64(unsafe.Sizeof(entryItem{}))
	if h.compact() {
		itemSize = uint64(unsafe.Sizeof(entryItemCompact{}))
	}
	n, err := itemCount(oh, fixedSize, itemSize)
	if err != nil {
		return nil, err
	}

	if err := read(r, &o.Fields); err != nil {
		return nil, err
	}

	if h.compact() {
		items := make([]entryItemCompact, n)
		if err := read(r, items); err != nil {
			return nil, err
		}
		o.Items = make([]entryItem, len(items))
		for i, item := range items {
			// uint64(uint32) rather than a plain conversion of a signed
			// value: an offset with bit 31 set must not sign-extend.
			o.Items[i] = entryItem{ObjectOffset: uint64(item.ObjectOffset)}
		}
		return &o, nil
	}

	o.Items = make([]entryItem, n)
	if err := read(r, o.Items); err != nil {
		return nil, err
	}
	return &o, nil
}

func readEntryArrayObject(h header, r *bytes.Reader, oh objectHeader) (*entryArrayObject, error) {
	var o entryArrayObject

	fixedSize := uint64(unsafe.Sizeof(o.Fields))
	itemSize := uint64(unsafe.Sizeof(uint64(0)))
	if h.compact() {
		itemSize = uint64(unsafe.Sizeof(uint32(0)))
	}
	n, err := itemCount(oh, fixedSize, itemSize)
	if err != nil {
		return nil, err
	}

	if err := read(r, &o.Fields); err != nil {
		return nil, err
	}

	if h.compact() {
		items := make([]uint32, n)
		if err := read(r, items); err != nil {
			return nil, err
		}
		o.Items = make([]uint64, len(items))
		for i, v := range items {
			o.Items[i] = uint64(v)
		}
		return &o, nil
	}

	o.Items = make([]uint64, n)
	if err := read(r, o.Items); err != nil {
		return nil, err
	}
	return &o, nil
}

func decompressZSTD(data []byte) ([]byte, error) {
	zr, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: zstd reader: %v", ErrCorrupt, err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("%w: zstd payload: %v", ErrCorrupt, err)
	}
	return out, nil
}

func read[T any](r io.Reader, t T) error {
	return binary.Read(r, binary.LittleEndian, t)
}
