//go:build linux

package journalx

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"

	"github.com/klauspost/compress/zstd"
)

// Sizes taken from the Go structs. Every test that lays out an object by
// hand derives its size field from these, so a struct that drifts from
// the on-disk format shows up as a parse failure rather than as a test
// that quietly agrees with the bug.
var (
	objHeaderSize         = uint64(unsafe.Sizeof(objectHeader{}))
	dataFieldsSize        = uint64(unsafe.Sizeof(dataObject{}.Fields))
	dataCompactFieldsSize = uint64(unsafe.Sizeof(dataObject{}.CompactFields))
	entryFieldsSize       = uint64(unsafe.Sizeof(entryObject{}.Fields))
	entryItemSize         = uint64(unsafe.Sizeof(entryItem{}))
	entryItemCompactSize  = uint64(unsafe.Sizeof(entryItemCompact{}))
	entryArrayFieldsSize  = uint64(unsafe.Sizeof(entryArrayObject{}.Fields))
	entryArrayItemSize    = uint64(8)
	entryArrayCompactItem = uint64(4)
)

// TestStructSizes pins every struct that mirrors an on-disk layout to
// the size systemd's packed C struct has.
//
// These numbers come from journal-def.h. They are asserted rather than
// assumed because Go does not pack structs: a field reordered or widened
// silently introduces padding, binary.Read keeps working because it
// ignores padding, and the size arithmetic in itemCount starts computing
// the wrong item count. This is the test that catches that.
//
// It is also what makes the format types the reader never walks
// (fieldObject, hashTableObject, tagObject) worth keeping: without it
// they would be unverified documentation.
func TestStructSizes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  uint64
		want uint64
	}{
		// struct Header, up to the fields this reader knows.
		{"header", uint64(unsafe.Sizeof(header{})), 208},
		{"sd_id128", uint64(unsafe.Sizeof(sdID128{})), 16},

		// struct ObjectHeader.
		{"objectHeader", uint64(unsafe.Sizeof(objectHeader{})), 16},

		// struct DataObject: 6 le64 after the object header, plus two
		// le32 in compact mode.
		{"dataObject.Fields", uint64(unsafe.Sizeof(dataObject{}.Fields)), 48},
		{"dataObject.CompactFields", uint64(unsafe.Sizeof(dataObject{}.CompactFields)), 8},

		// struct FieldObject: 3 le64 after the object header.
		{"fieldObject.Fields", uint64(unsafe.Sizeof(fieldObject{}.Fields)), 24},
		{"fieldObjectItem", uint64(unsafe.Sizeof(fieldObjectItem(0))), 1},

		// struct EntryObject: seqnum, realtime, monotonic, boot id, xor.
		{"entryObject.Fields", uint64(unsafe.Sizeof(entryObject{}.Fields)), 48},
		{"entryItem", uint64(unsafe.Sizeof(entryItem{})), 16},
		{"entryItemCompact", uint64(unsafe.Sizeof(entryItemCompact{})), 4},

		// struct EntryArrayObject: one le64 link before the items.
		{"entryArrayObject.Fields", uint64(unsafe.Sizeof(entryArrayObject{}.Fields)), 8},

		// struct HashItem and the table that holds them.
		{"hashItem", uint64(unsafe.Sizeof(hashItem{})), 16},

		// struct TagObject: seqnum, epoch, and a SHA-256 HMAC.
		{"tagObject", uint64(unsafe.Sizeof(tagObject{})), 48},
		{"tagLength", uint64(tagLength), 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("sizeof(%s) = %d, want %d (on-disk layout changed or Go added padding)",
					tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestHashTableObjectShape checks the one hash table field the header
// dump relies on: that a table is a whole number of buckets.
func TestHashTableObjectShape(t *testing.T) {
	t.Parallel()
	var table hashTableObject
	table.Items = make([]hashItem, 3)
	if got := uint64(len(table.Items)) * uint64(unsafe.Sizeof(hashItem{})); got != 48 {
		t.Errorf("3 buckets = %d bytes, want 48", got)
	}
}

// --- helpers -----------------------------------------------------------------

// testHeader returns a header suitable for readObject dispatch. Only the
// incompatible flags are meaningful.
func testHeader(compact bool) header {
	var flags uint32
	if compact {
		flags |= incompatibleCompact
	}
	return header{IncompatibleFlags: flags}
}

// readTestObject parses buf as a single object. The reader is given the
// whole buffer, which is what readObject uses to reject an object
// claiming to be bigger than its file.
func readTestObject(t *testing.T, h header, buf []byte) (any, error) {
	t.Helper()
	return readObject(h, bytes.NewReader(buf))
}

// --- flag validation ---------------------------------------------------------

func TestValidateIncompatibleFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		flags   uint32
		wantErr bool
	}{
		{"zero flags", 0, false},
		{"ZSTD only", incompatibleCompressedZSTD, false},
		{"keyed hash only", incompatibleKeyedHash, false},
		{"compact only", incompatibleCompact, false},
		{"all supported", supportedIncompatibleFlags, false},
		{"XZ rejected", incompatibleCompressedXZ, true},
		{"LZ4 rejected", incompatibleCompressedLZ4, true},
		{"unknown bit rejected", 1 << 5, true},
		{"LZ4 plus supported rejected", incompatibleCompressedLZ4 | incompatibleCompact, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateIncompatibleFlags(tt.flags)
			switch {
			case tt.wantErr && err == nil:
				t.Fatal("expected an error, got nil")
			case !tt.wantErr && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr && !errors.Is(err, ErrUnsupportedFlags):
				t.Fatalf("error does not match ErrUnsupportedFlags: %v", err)
			}
		})
	}
}

// --- itemCount ---------------------------------------------------------------

// TestItemCountRejectsUndersizedObject is a regression test.
//
// itemCount subtracts the fixed overhead from the size in the object
// header using unsigned arithmetic. Before the check, an object header
// reporting a size below that overhead wrapped around to roughly 2^64,
// and the caller passed the result straight to make. A journal file is
// mapped while systemd appends to it, so an object header that arrives
// before its payload is ordinary; the result was a panic or an
// out-of-memory kill on a perfectly healthy file.
func TestItemCountRejectsUndersizedObject(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		size      uint64
		fixedSize uint64
		itemSize  uint64
		wantErr   bool
		wantCount uint64
	}{
		{"zero size", 0, entryFieldsSize, entryItemSize, true, 0},
		{"header only", objHeaderSize, entryFieldsSize, entryItemSize, true, 0},
		{"one byte short", objHeaderSize + entryFieldsSize - 1, entryFieldsSize, entryItemSize, true, 0},
		{"exactly overhead", objHeaderSize + entryFieldsSize, entryFieldsSize, entryItemSize, false, 0},
		{"one item", objHeaderSize + entryFieldsSize + entryItemSize, entryFieldsSize, entryItemSize, false, 1},
		{"two items", objHeaderSize + entryFieldsSize + 2*entryItemSize, entryFieldsSize, entryItemSize, false, 2},
		{"partial item rounds down", objHeaderSize + entryFieldsSize + entryItemSize + 3, entryFieldsSize, entryItemSize, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := itemCount(objectHeader{Type: objectEntry, Size: tt.size}, tt.fixedSize, tt.itemSize)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("itemCount(size=%d) = %d, want an error", tt.size, got)
				}
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("error does not match ErrCorrupt: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantCount {
				t.Errorf("itemCount(size=%d) = %d, want %d", tt.size, got, tt.wantCount)
			}
		})
	}
}

// TestReadObjectRejectsUndersizedEntry drives the same defect through
// the parser, which is the path a corrupt file actually takes.
func TestReadObjectRejectsUndersizedEntry(t *testing.T) {
	t.Parallel()
	for _, compact := range []bool{false, true} {
		name := "regular"
		if compact {
			name = "compact"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			// A size of 1 cannot even cover the object header.
			writeObjectHeader(&buf, objectEntry, 0, 1)
			writeZeros(&buf, int(entryFieldsSize))

			_, err := readTestObject(t, testHeader(compact), buf.Bytes())
			if err == nil {
				t.Fatal("expected an error for an undersized entry, got nil")
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error does not match ErrCorrupt: %v", err)
			}
		})
	}
}

// TestReadObjectRejectsOversizedObject is the other half of the
// allocation bound, and it is the test that would fail loudly if the
// bound were removed.
//
// An object header claiming a terabyte, which is what a wild offset
// looks like once it lands on plausible bytes, must not reach make: the
// item count derived from that size is about 6.8e10 entry items, so the
// allocation attempt is roughly 1.1TB. It is reported as incomplete
// rather than as corruption, because the same shape occurs benignly at
// the tail of a file being appended to.
func TestReadObjectRejectsOversizedObject(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		typ  uint8
	}{
		{"data", objectData},
		{"entry", objectEntry},
		{"entry array", objectEntryArray},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			writeObjectHeader(&buf, tt.typ, 0, 1<<40)
			writeZeros(&buf, int(entryFieldsSize))

			_, err := readTestObject(t, testHeader(false), buf.Bytes())
			if err == nil {
				t.Fatal("expected an error for an object larger than the file, got nil")
			}
			if !incomplete(err) {
				t.Fatalf("error = %v, want an EOF that Follow can wait on", err)
			}
		})
	}
}

// --- data objects ------------------------------------------------------------

func TestReadDataObject(t *testing.T) {
	t.Parallel()

	t.Run("non-compact", func(t *testing.T) {
		t.Parallel()
		payload := []byte("MESSAGE=hello world")

		var buf bytes.Buffer
		size := objHeaderSize + dataFieldsSize + uint64(len(payload))
		writeObjectHeader(&buf, objectData, 0, size)
		writeZeros(&buf, int(dataFieldsSize))
		buf.Write(payload)

		obj, err := readTestObject(t, testHeader(false), buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if got := obj.(*dataObject).Payload; !bytes.Equal(got, payload) {
			t.Fatalf("payload = %q, want %q", got, payload)
		}
	})

	// Regression: the compact layout puts two le32 between the fixed
	// fields and the payload. Reading the payload without skipping them
	// returned the wrong bytes and the wrong length.
	t.Run("compact payload offset", func(t *testing.T) {
		t.Parallel()
		payload := []byte("MESSAGE=hello compact")

		var buf bytes.Buffer
		size := objHeaderSize + dataFieldsSize + dataCompactFieldsSize + uint64(len(payload))
		writeObjectHeader(&buf, objectData, 0, size)
		writeZeros(&buf, int(dataFieldsSize))
		writeZeros(&buf, int(dataCompactFieldsSize))
		buf.Write(payload)

		obj, err := readTestObject(t, testHeader(true), buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if got := obj.(*dataObject).Payload; !bytes.Equal(got, payload) {
			t.Fatalf("payload = %q, want %q", got, payload)
		}
	})

	t.Run("zstd", func(t *testing.T) {
		t.Parallel()
		for _, compact := range []bool{false, true} {
			name := "regular"
			if compact {
				name = "compact"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				original := []byte("MESSAGE=compressed payload")
				zdata := compressZSTD(t, original)

				var buf bytes.Buffer
				size := objHeaderSize + dataFieldsSize + uint64(len(zdata))
				if compact {
					size += dataCompactFieldsSize
				}
				writeObjectHeader(&buf, objectData, objectCompressedZSTD, size)
				writeZeros(&buf, int(dataFieldsSize))
				if compact {
					writeZeros(&buf, int(dataCompactFieldsSize))
				}
				buf.Write(zdata)

				obj, err := readTestObject(t, testHeader(compact), buf.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				if got := obj.(*dataObject).Payload; !bytes.Equal(got, original) {
					t.Fatalf("decompressed = %q, want %q", got, original)
				}
			})
		}
	})

	t.Run("invalid zstd is corruption", func(t *testing.T) {
		t.Parallel()
		garbage := []byte("not valid zstd data at all!!")

		var buf bytes.Buffer
		size := objHeaderSize + dataFieldsSize + uint64(len(garbage))
		writeObjectHeader(&buf, objectData, objectCompressedZSTD, size)
		writeZeros(&buf, int(dataFieldsSize))
		buf.Write(garbage)

		_, err := readTestObject(t, testHeader(false), buf.Bytes())
		if err == nil {
			t.Fatal("expected an error for invalid zstd, got nil")
		}
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error does not match ErrCorrupt: %v", err)
		}
	})

	// XZ and LZ4 are rejected per file by the header check, but a single
	// object can also carry the flag, and that has to name the feature
	// rather than look like corruption.
	t.Run("unsupported compression names the codec", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name  string
			flags uint8
		}{
			{"xz", objectCompressedXZ},
			{"lz4", objectCompressedLZ4},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				payload := []byte("MESSAGE=x")

				var buf bytes.Buffer
				size := objHeaderSize + dataFieldsSize + uint64(len(payload))
				writeObjectHeader(&buf, objectData, tt.flags, size)
				writeZeros(&buf, int(dataFieldsSize))
				buf.Write(payload)

				_, err := readTestObject(t, testHeader(false), buf.Bytes())
				if !errors.Is(err, ErrUnsupportedFlags) {
					t.Fatalf("error = %v, want ErrUnsupportedFlags", err)
				}
			})
		}
	})
}

// --- entry objects -----------------------------------------------------------

func TestReadEntryObject(t *testing.T) {
	t.Parallel()

	t.Run("non-compact", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		nItems := uint64(2)
		size := objHeaderSize + entryFieldsSize + nItems*entryItemSize
		writeObjectHeader(&buf, objectEntry, 0, size)
		writeU64(&buf, 42)         // seqnum
		writeU64(&buf, 1000000)    // realtime
		writeU64(&buf, 500000)     // monotonic
		writeZeros(&buf, 16)       // boot id
		writeU64(&buf, 0xdeadbeef) // xor hash
		writeU64(&buf, 100)        // item 0 offset
		writeU64(&buf, 200)        // item 0 hash
		writeU64(&buf, 300)        // item 1 offset
		writeU64(&buf, 400)        // item 1 hash

		obj, err := readTestObject(t, testHeader(false), buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		e := obj.(*entryObject)
		if e.Fields.Seqnum != 42 {
			t.Errorf("seqnum = %d, want 42", e.Fields.Seqnum)
		}
		if len(e.Items) != 2 {
			t.Fatalf("len(items) = %d, want 2", len(e.Items))
		}
		if e.Items[0].ObjectOffset != 100 || e.Items[1].ObjectOffset != 300 {
			t.Errorf("offsets = %d,%d, want 100,300",
				e.Items[0].ObjectOffset, e.Items[1].ObjectOffset)
		}
	})

	// Regression: a compact offset is an unsigned 32-bit value. Widening
	// it through a signed type sign-extends anything with bit 31 set,
	// producing an offset near 2^64.
	t.Run("compact offset does not sign extend", func(t *testing.T) {
		t.Parallel()
		const largeOffset uint32 = 0x80000001

		var buf bytes.Buffer
		size := objHeaderSize + entryFieldsSize + entryItemCompactSize
		writeObjectHeader(&buf, objectEntry, 0, size)
		writeU64(&buf, 1)
		writeU64(&buf, 0)
		writeU64(&buf, 0)
		writeZeros(&buf, 16)
		writeU64(&buf, 0)
		writeU32(&buf, largeOffset)

		obj, err := readTestObject(t, testHeader(true), buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		e := obj.(*entryObject)
		if len(e.Items) != 1 {
			t.Fatalf("len(items) = %d, want 1", len(e.Items))
		}
		if got, want := e.Items[0].ObjectOffset, uint64(largeOffset); got != want {
			t.Errorf("offset = %#x, want %#x", got, want)
		}
	})
}

// --- entry arrays ------------------------------------------------------------

func TestReadEntryArrayObject(t *testing.T) {
	t.Parallel()

	t.Run("non-compact", func(t *testing.T) {
		t.Parallel()
		offsets := []uint64{1000, 2000, 3000}

		var buf bytes.Buffer
		size := objHeaderSize + entryArrayFieldsSize + uint64(len(offsets))*entryArrayItemSize
		writeObjectHeader(&buf, objectEntryArray, 0, size)
		writeU64(&buf, 0) // next entry array offset
		for _, o := range offsets {
			writeU64(&buf, o)
		}

		obj, err := readTestObject(t, testHeader(false), buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		ea := obj.(*entryArrayObject)
		if len(ea.Items) != len(offsets) {
			t.Fatalf("len(items) = %d, want %d", len(ea.Items), len(offsets))
		}
		for i, want := range offsets {
			if ea.Items[i] != want {
				t.Errorf("items[%d] = %d, want %d", i, ea.Items[i], want)
			}
		}
	})

	t.Run("compact offset does not sign extend", func(t *testing.T) {
		t.Parallel()
		const largeOffset uint32 = 0x80000001

		var buf bytes.Buffer
		size := objHeaderSize + entryArrayFieldsSize + entryArrayCompactItem
		writeObjectHeader(&buf, objectEntryArray, 0, size)
		writeU64(&buf, 0)
		writeU32(&buf, largeOffset)

		obj, err := readTestObject(t, testHeader(true), buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		ea := obj.(*entryArrayObject)
		if len(ea.Items) != 1 {
			t.Fatalf("len(items) = %d, want 1", len(ea.Items))
		}
		if got, want := ea.Items[0], uint64(largeOffset); got != want {
			t.Errorf("offset = %#x, want %#x", got, want)
		}
	})

	t.Run("next offset preserved", func(t *testing.T) {
		t.Parallel()
		const nextOffset uint64 = 0xCAFE

		var buf bytes.Buffer
		size := objHeaderSize + entryArrayFieldsSize + entryArrayItemSize
		writeObjectHeader(&buf, objectEntryArray, 0, size)
		writeU64(&buf, nextOffset)
		writeU64(&buf, 500)

		obj, err := readTestObject(t, testHeader(false), buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if got := obj.(*entryArrayObject).Fields.NextEntryArrayOffset; got != nextOffset {
			t.Errorf("next = %#x, want %#x", got, nextOffset)
		}
	})
}

// --- dispatch ----------------------------------------------------------------

func TestReadObjectUnknownType(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	writeObjectHeader(&buf, objectTypeMax+1, 0, objHeaderSize)

	_, err := readTestObject(t, testHeader(false), buf.Bytes())
	if err == nil {
		t.Fatal("expected an error for an unknown object type, got nil")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error does not match ErrCorrupt: %v", err)
	}
}

// TestReadObjectTruncated covers the case the reader must not treat as
// corruption: an object header present with its payload not yet written.
// It has to surface as an EOF so that Follow waits instead of failing.
func TestReadObjectTruncated(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	size := objHeaderSize + entryFieldsSize + entryItemSize
	writeObjectHeader(&buf, objectEntry, 0, size)
	// Fixed fields deliberately absent.

	_, err := readTestObject(t, testHeader(false), buf.Bytes())
	if err == nil {
		t.Fatal("expected an error for a truncated object, got nil")
	}
	if !incomplete(err) {
		t.Fatalf("error = %v, want an EOF that Follow can wait on", err)
	}
	if errors.Is(err, ErrCorrupt) {
		t.Fatal("a truncated tail must not be reported as corruption")
	}
}

// TestDecompressZSTDEmpty guards the boundary the compressor is allowed
// to produce: a zero-length payload is valid, not corrupt.
func TestDecompressZSTDEmpty(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := decompressZSTD(out.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("payload = %q, want empty", got)
	}
}
