//go:build linux

package journalx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// errReplaced reports that a name no longer refers to the inode mapped
// under it. It is internal: scan is the only caller that can act on it,
// and it does so by reopening the name.
const errReplaced Error = "journalx: file replaced"

// journalFile is one mapped journal file and the reader's position in it.
//
// The position is an offset into the entry array chain plus an index
// within that array, rather than a sequence number to compare against.
// That is what lets the merge in Follow ask each file for its next entry
// cheaply, which it does once per emitted entry across every open file.
// Field order is set by betteralign rather than by what reads best: the
// pointer-bearing fields come first so the GC has a shorter prefix to
// scan, and buf is last among them because a slice puts its pointer
// first and its length and capacity after, so trailing it keeps the
// final pointer word at a lower offset.
type journalFile struct {
	r *bytes.Reader

	// name is the base name within the journal directory. It is the
	// file's identity for the reader: rotation replaces the contents
	// behind a name, and vacuuming removes a name.
	name string
	path string

	buf []byte
	h   header

	// dev and ino identify the inode that buf maps.
	//
	// They are the reason a name is not enough. A mapping is bound to an
	// inode, not to a path, so after a rotation the name refers to a new
	// file while the mapping still shows the old one. Sizes are no help
	// either: two journal files holding the same entries are the same
	// length, so the replacement can be byte-for-byte as long as what it
	// replaced.
	dev uint64
	ino uint64

	// array is the offset of the entry array being walked and slot is
	// the index within it.
	array uint64
	slot  int
}

// openJournalFile maps the named file in dir and reads its header.
func openJournalFile(dir, name string) (*journalFile, error) {
	path := filepath.Join(dir, name)

	buf, st, err := mapFile(path)
	if err != nil {
		return nil, err
	}

	f := &journalFile{
		name: name,
		path: path,
		buf:  buf,
		r:    bytes.NewReader(buf),
		dev:  uint64(st.Dev),
		ino:  uint64(st.Ino),
	}
	if err := f.readHeader(); err != nil {
		unix.Munmap(buf) //nolint:errcheck
		return nil, err
	}
	f.array = f.h.EntryArrayOffset
	return f, nil
}

// close releases the mapping.
func (f *journalFile) close() error {
	if f.buf == nil {
		return nil
	}
	buf := f.buf
	f.buf, f.r = nil, nil
	if err := unix.Munmap(buf); err != nil {
		return fmt.Errorf("journalx: munmap %s: %w", f.path, err)
	}
	return nil
}

// refresh extends the mapping over a file that has grown and re-reads
// the header.
//
// The position in the entry array chain is preserved: growth appends
// entries and fills in slots, it does not move what is already there.
//
// It returns errReplaced when the name no longer refers to the mapped
// inode, which is what a rotation looks like from here. The caller has
// to reopen rather than remap: nothing about the old mapping describes
// the new file, and the position in it is meaningless.
func (f *journalFile) refresh() error {
	var st unix.Stat_t
	if err := unix.Stat(f.path, &st); err != nil {
		return fmt.Errorf("journalx: stat %s: %w", f.path, err)
	}
	if uint64(st.Dev) != f.dev || uint64(st.Ino) != f.ino {
		return errReplaced
	}

	switch size := int(st.Size); {
	case size == len(f.buf):
		// The write landed inside the region already mapped. Nothing to
		// remap, but the header still has to be re-read: its tail
		// counters move with every entry.
	case size < len(f.buf):
		// Same inode, fewer bytes. A journal file is append-only, so it
		// was truncated under us and neither the mapping nor the
		// position describes it any more.
		return fmt.Errorf("%w: %s shrank from %d to %d bytes",
			ErrCorrupt, f.path, len(f.buf), size)
	default:
		buf, err := unix.Mremap(f.buf, size, unix.MREMAP_MAYMOVE)
		if err != nil {
			return fmt.Errorf("journalx: mremap %s: %w", f.path, err)
		}
		f.buf = buf
		f.r = bytes.NewReader(buf)
	}
	return f.readHeader()
}

// readHeader reads the file header from the current mapping.
func (f *journalFile) readHeader() error {
	if err := f.seek(0); err != nil {
		return err
	}
	if err := read(f.r, &f.h); err != nil {
		return fmt.Errorf("journalx: read header of %s: %w", f.path, err)
	}
	if !bytes.Equal(f.h.Signature[:], []byte(journalSignature)) {
		return fmt.Errorf("%w: %s is not a journal file", ErrCorrupt, f.path)
	}
	return validateIncompatibleFlags(f.h.IncompatibleFlags)
}

// next returns this file's next unread entry, or nil when the file holds
// nothing further yet.
//
// Nothing-yet is the normal outcome, not a fault: the file is mapped
// while systemd appends to it, so the reader runs off the written data
// on every pass and waits for the directory to change.
func (f *journalFile) next() (*entryObject, error) {
	for {
		array, err := f.arrayAt(f.array)
		if err != nil {
			if incomplete(err) {
				return nil, nil
			}
			return nil, err
		}

		if f.slot >= array.capacity {
			// This array is full. Follow the chain, or stop if the next
			// one has not been allocated yet.
			if array.next == 0 {
				return nil, nil
			}
			f.array = array.next
			f.slot = 0
			continue
		}

		offset, err := f.slotAt(array, f.slot)
		if err != nil {
			if incomplete(err) {
				return nil, nil
			}
			return nil, err
		}
		if offset == 0 {
			// A preallocated slot that has not been written yet. Slots
			// fill in order, so there is nothing beyond it either.
			return nil, nil
		}

		entry, err := f.entryAt(offset)
		if err != nil {
			if incomplete(err) {
				return nil, nil
			}
			return nil, err
		}
		f.slot++
		return entry, nil
	}
}

// arrayRef is the fixed part of an entry array: enough to index its
// slots without reading them.
//
// The whole array is deliberately not parsed. Replaying a large journal
// asks for the next entry once per entry, and systemd grows entry arrays
// up to thousands of slots, so parsing the array each time would be
// quadratic in the number of entries and would allocate the slot slice
// on every step. Caching the parsed copy instead would go stale exactly
// when it matters, because slots are filled in behind the reader.
type arrayRef struct {
	// base is the file offset of slot zero.
	base uint64

	// next is the offset of the following array, zero if unallocated.
	next uint64

	capacity int

	// itemSize is 4 in compact files and 8 otherwise.
	itemSize uint64
}

// arrayAt reads the fixed part of the entry array at offset.
func (f *journalFile) arrayAt(offset uint64) (arrayRef, error) {
	if err := f.seek(offset); err != nil {
		return arrayRef{}, err
	}

	var oh objectHeader
	if err := read(f.r, &oh); err != nil {
		return arrayRef{}, err
	}
	if err := f.checkObject(oh, offset, objectEntryArray); err != nil {
		return arrayRef{}, err
	}

	var link struct{ NextEntryArrayOffset uint64 }
	if err := read(f.r, &link); err != nil {
		return arrayRef{}, err
	}

	itemSize := uint64(8)
	if f.h.compact() {
		itemSize = 4
	}
	fixed := uint64(unsafe.Sizeof(link))
	capacity, err := itemCount(oh, fixed, itemSize)
	if err != nil {
		return arrayRef{}, err
	}

	return arrayRef{
		base:     offset + uint64(unsafe.Sizeof(oh)) + fixed,
		next:     link.NextEntryArrayOffset,
		capacity: int(capacity),
		itemSize: itemSize,
	}, nil
}

// slotAt reads one entry offset out of an entry array.
func (f *journalFile) slotAt(array arrayRef, slot int) (uint64, error) {
	if err := f.seek(array.base + uint64(slot)*array.itemSize); err != nil {
		return 0, err
	}
	if array.itemSize == 4 {
		var offset uint32
		if err := read(f.r, &offset); err != nil {
			return 0, err
		}
		// Converted from the unsigned type so that an offset with bit 31
		// set does not sign-extend.
		return uint64(offset), nil
	}
	var offset uint64
	if err := read(f.r, &offset); err != nil {
		return 0, err
	}
	return offset, nil
}

// entryAt reads the entry object at offset.
func (f *journalFile) entryAt(offset uint64) (*entryObject, error) {
	obj, err := f.objectAt(offset)
	if err != nil {
		return nil, err
	}
	entry, ok := obj.(*entryObject)
	if !ok {
		return nil, fmt.Errorf("%w: %s offset %d is %T, want an entry",
			ErrCorrupt, f.path, offset, obj)
	}
	return entry, nil
}

// dataAt reads the data object at offset.
func (f *journalFile) dataAt(offset uint64) (*dataObject, error) {
	obj, err := f.objectAt(offset)
	if err != nil {
		return nil, err
	}
	data, ok := obj.(*dataObject)
	if !ok {
		return nil, fmt.Errorf("%w: %s offset %d is %T, want a data object",
			ErrCorrupt, f.path, offset, obj)
	}
	return data, nil
}

// objectAt seeks to offset and reads whatever object is there.
func (f *journalFile) objectAt(offset uint64) (any, error) {
	if err := f.seek(offset); err != nil {
		return nil, err
	}
	return readObject(f.h, f.r)
}

// checkObject rejects an object header that cannot describe an object of
// the wanted type at this offset.
func (f *journalFile) checkObject(oh objectHeader, offset uint64, want uint8) error {
	if oh.Type != want {
		return fmt.Errorf("%w: %s offset %d is object type %d, want %d",
			ErrCorrupt, f.path, offset, oh.Type, want)
	}
	headerLen := uint64(unsafe.Sizeof(oh))
	if oh.Size < headerLen {
		return fmt.Errorf("%w: %s offset %d size %d below the %d byte object header",
			ErrCorrupt, f.path, offset, oh.Size, headerLen)
	}
	if body := oh.Size - headerLen; body > uint64(f.r.Len()) {
		return fmt.Errorf("%s offset %d wants %d bytes of body, %d available: %w",
			f.path, offset, body, f.r.Len(), io.ErrUnexpectedEOF)
	}
	return nil
}

// seek positions the reader, reporting an offset outside the mapping as
// an unexpected EOF.
//
// It reads as corruption but usually is not. The mapping is only
// extended between passes, while the file grows continuously, so an
// entry array slot read part-way through a pass can already point past
// the end of what is mapped. Treating that as fatal would turn ordinary
// concurrent appends into an error.
//
// The reader's response is to stop the pass and wait, and that is safe
// here for a specific reason: the write that filled the slot generated a
// change notification of its own, which is still queued because
// notifications are only consumed after a pass finishes. So there is
// always another wake-up coming, and the next pass sees a mapping that
// covers the entry.
//
// A genuinely wild offset stalls the stream instead of reporting, which
// is the same trade-off readObject makes for an oversized object body,
// and for the same reason: the alternative is failing on healthy files.
func (f *journalFile) seek(offset uint64) error {
	if offset > uint64(len(f.buf)) {
		return fmt.Errorf("%s offset %d beyond %d mapped bytes: %w",
			f.path, offset, len(f.buf), io.ErrUnexpectedEOF)
	}
	if _, err := f.r.Seek(int64(offset), io.SeekStart); err != nil {
		return fmt.Errorf("journalx: seek %s to %d: %w", f.path, offset, err)
	}
	return nil
}

// mapFile maps a whole file read-only and reports the inode it mapped.
//
// The stat comes from the open descriptor rather than from the path, so
// what it describes is exactly what got mapped even if the name is
// replaced in between.
func mapFile(path string) ([]byte, unix.Stat_t, error) {
	var st unix.Stat_t

	file, err := os.Open(path)
	if err != nil {
		// os.Open already names the path in its PathError.
		return nil, st, fmt.Errorf("journalx: %w", err)
	}
	defer file.Close() //nolint:errcheck

	if err = unix.Fstat(int(file.Fd()), &st); err != nil {
		return nil, st, fmt.Errorf("journalx: fstat %s: %w", path, err)
	}
	if st.Size == 0 {
		return nil, st, fmt.Errorf("journalx: %s is empty", path)
	}

	// MAP_SHARED rather than MAP_PRIVATE so that extending the mapping
	// through mremap sees what systemd has written since it was made.
	buf, err := unix.Mmap(int(file.Fd()), 0, int(st.Size), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, st, fmt.Errorf("journalx: mmap %s: %w", path, err)
	}
	return buf, st, nil
}

// incomplete reports whether err means "the rest has not been written
// yet" rather than "this file is broken".
//
// The distinction matters because a journal file is mapped while systemd
// appends to it, so reading off the end of the written data is routine.
// It is not reported to the caller: the reader waits for the directory
// to change and tries again.
func incomplete(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
