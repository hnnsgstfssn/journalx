//go:build linux

package journalx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Journal streams entries from a systemd journal directory.
//
// A Journal is not safe for concurrent use. Follow owns every field for
// as long as it runs, which is what lets it remap files and open new
// ones underneath itself without locking. Two readers of the same
// directory should Open it twice: the kernel shares the page cache, so
// the only duplicated cost is page tables.
type Journal struct {
	dir string

	// files are the journal files currently open, keyed by base name.
	// Rotation replaces the contents behind a name and vacuuming removes
	// one, so the name is the file's identity here.
	files map[string]*journalFile

	// pending is each open file's next unreported entry, keyed the same
	// way. It is the lookahead the merge picks from.
	pending map[string]*entryObject

	// seen is the highest sequence number already reported for each
	// sequence ID. Sequence numbers are only comparable within one ID,
	// so this is a map rather than a single counter, and it is what makes
	// re-reading a file idempotent.
	seen map[sdID128]uint64

	// skipped holds why each file the last scan could not open was
	// skipped. Kept so that a directory in which nothing is readable can
	// report the reason rather than just the count.
	skipped []error

	closed bool
}

// Open prepares to read every journal file in dir.
//
// dir is a journal directory, not a file: typically
// /var/log/journal/<machine-id> for the persistent journal or
// /run/log/journal/<machine-id> for the volatile one. Every *.journal
// file in it is read, and files that appear later are picked up.
//
// Reading starts at the oldest entry the directory still holds, so a
// Follow that begins now replays what is already on disk before it waits
// for anything new.
//
// A file that cannot be opened or whose header cannot be parsed is
// skipped rather than failing the whole directory, because one unclean
// file must not stop the stream. Open fails only if the directory cannot
// be read, or if it holds journal files and none of them could be
// opened.
//
// The caller must Close the result.
func Open(dir string) (*Journal, error) {
	if dir == "" {
		return nil, fmt.Errorf("journalx: empty directory")
	}

	j := &Journal{
		dir:     dir,
		files:   map[string]*journalFile{},
		pending: map[string]*entryObject{},
		seen:    map[sdID128]uint64{},
	}

	found, err := j.scan()
	if err != nil {
		return nil, err
	}
	if found > 0 && len(j.files) == 0 {
		// Skipping an unreadable file is right when others work, but a
		// directory where nothing works is a failure, and it has to
		// carry the reasons: "none readable" on its own tells an
		// operator nothing about what to fix.
		return nil, fmt.Errorf("journalx: %s holds %d journal files, none readable: %w",
			dir, found, errors.Join(j.skipped...))
	}
	return j, nil
}

// Close releases every mapping. It is safe to call more than once.
func (j *Journal) Close() error {
	if j.closed {
		return nil
	}
	j.closed = true

	var errs []error
	for _, name := range slices.Sorted(maps.Keys(j.files)) {
		if err := j.files[name].close(); err != nil {
			errs = append(errs, err)
		}
	}
	clear(j.files)
	clear(j.pending)
	return errors.Join(errs...)
}

// Follow streams journal entries to handler until ctx is cancelled.
//
// It drains everything the directory already holds, then waits for the
// directory to change and drains again, extending mappings over files
// that grew and opening files that appeared. It returns nil on
// cancellation and an error only when the journal cannot be read.
func (j *Journal) Follow(ctx context.Context, handler slog.Handler) error {
	// The watch is established before the first scan, so a file that
	// appears while the scan is running still produces an event that is
	// waiting by the time the reader parks.
	w, err := newWatcher(j.dir)
	if err != nil {
		return err
	}
	defer w.Close() //nolint:errcheck

	// The watcher read blocks in the runtime poller and cannot take a
	// context, so cancellation closes the descriptor to interrupt it.
	// stop covers the ordinary return path, so this goroutine cannot
	// outlive Follow, and the deferred Wait is what lets a caller rely on
	// that.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	defer wg.Wait()
	defer close(stop)
	wg.Go(func() {
		select {
		case <-ctx.Done():
			w.Close() //nolint:errcheck
		case <-stop:
		}
	})

	for {
		// Scan before draining, every time round. Open scanned already,
		// but a file created between Open and here would otherwise stay
		// invisible until some later change happened to wake the reader,
		// which on a freshly booted system means the first journal file
		// of all.
		if _, err := j.scan(); err != nil {
			return err
		}
		if err := j.drain(ctx, handler); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}

		if err := w.next(); err != nil {
			// A closed descriptor is how cancellation reaches us. Any
			// other read failure is real.
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

// drain reports every entry now readable, oldest first, and returns when
// no file has another entry to contribute.
func (j *Journal) drain(ctx context.Context, handler slog.Handler) error {
	for {
		// Checked per entry rather than per pass: replaying a large
		// directory takes a while, and a caller cancelling should not
		// have to wait for all of it.
		if ctx.Err() != nil {
			return nil
		}

		name, entry, err := j.oldest()
		if err != nil {
			return err
		}
		if entry == nil {
			return nil
		}
		delete(j.pending, name)

		// The sequence ID comes from the file header, not the entry: it
		// identifies the journal the entry was written to, which is what
		// makes its sequence number comparable.
		id := j.files[name].h.SeqnumID
		if entry.Fields.Seqnum <= j.seen[id] {
			// Already reported. This happens whenever a file is re-read
			// after growing, and it is the reason the high-water mark
			// exists rather than a per-file cursor alone.
			continue
		}
		j.seen[id] = entry.Fields.Seqnum

		record, err := j.record(j.files[name], entry)
		if err != nil {
			if incomplete(err) {
				return nil
			}
			return err
		}
		if err := handler.Handle(ctx, record); err != nil {
			return fmt.Errorf("journalx: handle entry %d: %w", entry.Fields.Seqnum, err)
		}
	}
}

// oldest returns the next entry to report, and the file it came from.
//
// The ordering is the one systemd's own tooling uses. Within a single
// sequence ID, which is what a journal and its rotated archives share,
// sequence numbers are dense and authoritative, so they order the
// entries exactly. Across sequence IDs, a system journal and a user
// journal for instance, sequence numbers are unrelated and the only
// thing comparable is the wall clock.
//
// A nil entry with no error means nothing further is readable yet.
func (j *Journal) oldest() (string, *entryObject, error) {
	// Refill the lookahead for any file that does not have one.
	for _, name := range slices.Sorted(maps.Keys(j.files)) {
		if _, ok := j.pending[name]; ok {
			continue
		}
		entry, err := j.files[name].next()
		if err != nil {
			return "", nil, err
		}
		if entry != nil {
			j.pending[name] = entry
		}
	}

	var (
		bestName  string
		bestEntry *entryObject
		bestID    sdID128
	)
	for _, name := range slices.Sorted(maps.Keys(j.pending)) {
		entry := j.pending[name]
		id := j.files[name].h.SeqnumID
		if bestEntry == nil || earlier(id, entry, bestID, bestEntry) {
			bestName, bestEntry, bestID = name, entry, id
		}
	}
	return bestName, bestEntry, nil
}

// earlier reports whether entry a should be reported before entry b.
func earlier(aID sdID128, a *entryObject, bID sdID128, b *entryObject) bool {
	if aID == bID {
		return a.Fields.Seqnum < b.Fields.Seqnum
	}
	return a.Fields.Realtime < b.Fields.Realtime
}

// scan brings the set of open files in line with the directory,
// returning how many journal files it saw.
//
// This is the whole response to a change notification: a file that grew
// is remapped, a file that appeared is opened, and a file that went away
// is closed. Doing it by rescanning rather than by interpreting events
// is what makes rotation work, since a rename and the creation of its
// replacement are two separate events with a window between them where
// the new name does not exist.
func (j *Journal) scan() (int, error) {
	names, err := journalFileNames(j.dir)
	if err != nil {
		return 0, err
	}

	// Drop files that are no longer there. Their entries have already
	// been reported, or they were vacuumed before being read, and
	// neither is recoverable.
	present := map[string]bool{}
	for _, name := range names {
		present[name] = true
	}
	j.skipped = j.skipped[:0]
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(j.files)) {
		if present[name] {
			continue
		}
		if err := j.files[name].close(); err != nil {
			errs = append(errs, err)
		}
		delete(j.files, name)
		delete(j.pending, name)
	}

	for _, name := range names {
		file, open := j.files[name]
		if !open {
			opened, err := openJournalFile(j.dir, name)
			if err != nil {
				// One unclean or half-written file must not stop the
				// stream. It is retried on the next change, by which
				// point systemd may have finished writing its header.
				j.skipped = append(j.skipped, err)
				continue
			}
			j.files[name] = opened
			continue
		}

		err := file.refresh()
		if err == nil {
			continue
		}

		// Whatever went wrong, this mapping no longer describes the file
		// behind the name, so drop it. errReplaced is the expected case
		// and means a rotation happened: the name is reopened below so
		// its entries are read from the start. Anything else is a file
		// that stopped making sense, and it is left closed until the
		// next change, by which point systemd may have finished with it.
		if cerr := file.close(); cerr != nil {
			errs = append(errs, cerr)
		}
		delete(j.files, name)
		delete(j.pending, name)

		if !errors.Is(err, errReplaced) {
			j.skipped = append(j.skipped, err)
			continue
		}
		replacement, err := openJournalFile(j.dir, name)
		if err != nil {
			j.skipped = append(j.skipped, err)
			continue
		}
		j.files[name] = replacement
	}
	return len(names), errors.Join(errs...)
}

// journalFileNames lists the journal files in dir, sorted.
//
// Both suffixes systemd uses are accepted. A plain .journal is a normal
// file, active or archived; a trailing tilde marks one systemd found
// unclean and rotated away, which journalctl still reads and so does
// this reader.
func journalFileNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("journalx: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".journal") || strings.HasSuffix(name, ".journal~") {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

// record converts one entry into an slog.Record.
//
// Field values are arbitrary binary: the journal export format defines a
// length-prefixed encoding precisely because a value may contain
// newlines or invalid UTF-8. A value that is valid UTF-8 becomes a
// string attribute; anything else is passed through as bytes so the
// handler decides how to render it, instead of being mangled into
// replacement characters here.
//
// A field name may legally repeat within one entry. Repeats collect into
// a single attribute holding all the values, mirroring what the journal
// JSON format does, rather than the last one winning.
//
// MESSAGE and PRIORITY are consumed to build the record's message and
// level and do not appear in the attributes. Only their first occurrence
// is used.
func (j *Journal) record(file *journalFile, entry *entryObject) (slog.Record, error) {
	var (
		message  string
		priority string
		names    []string // field names in first-seen order
		values   = make(map[string][][]byte, len(entry.Items))
	)

	for _, item := range entry.Items {
		data, err := file.dataAt(item.ObjectOffset)
		if err != nil {
			return slog.Record{}, err
		}

		name, value, ok := bytes.Cut(data.Payload, []byte("="))
		if !ok {
			// Not a NAME=value payload, so there is nothing the export
			// format could represent and nothing to report.
			continue
		}

		switch key := string(name); key {
		case "MESSAGE":
			if message == "" {
				message = string(value)
			}
		case "PRIORITY":
			if priority == "" {
				priority = string(value)
			}
		default:
			if _, seen := values[key]; !seen {
				names = append(names, key)
			}
			values[key] = append(values[key], value)
		}
	}

	record := slog.NewRecord(
		realtime(entry.Fields.Realtime),
		prioToLevel(priority),
		message,
		0, // no caller PC: the entry came from another process
	)
	for _, name := range names {
		record.AddAttrs(attr(name, values[name]))
	}
	return record, nil
}

// attr renders the values collected for one field name.
func attr(name string, values [][]byte) slog.Attr {
	if len(values) == 1 {
		return slog.Any(name, fieldValue(values[0]))
	}
	rendered := make([]any, len(values))
	for i, v := range values {
		rendered[i] = fieldValue(v)
	}
	return slog.Any(name, rendered)
}

// fieldValue keeps text as text and leaves binary as bytes.
func fieldValue(value []byte) any {
	if utf8.Valid(value) {
		// Converting to string copies, so the result does not point into
		// the mapping.
		return string(value)
	}
	// Cloned because value points into the mapped file, which is
	// replaced when the file next grows.
	return bytes.Clone(value)
}

// realtime converts a journal timestamp, microseconds since the Unix
// epoch, to a time.Time. A zero timestamp becomes the zero Time rather
// than 1970, so a handler cannot present a missing timestamp as a real
// one.
func realtime(usec uint64) time.Time {
	if usec == 0 {
		return time.Time{}
	}
	return time.UnixMicro(int64(usec))
}

// prioToLevel maps a syslog priority to an slog level. The mapping is
// lossy in both directions: syslog has eight levels to slog's four, and
// an entry with no PRIORITY field is reported at Warn so that a handler
// filtering at Info does not drop it silently.
func prioToLevel(priority string) slog.Level {
	switch priority {
	case "0", "1", "2", "3": // emerg, alert, crit, err
		return slog.LevelError
	case "4": // warning
		return slog.LevelWarn
	case "5", "6": // notice, info
		return slog.LevelInfo
	case "7": // debug
		return slog.LevelDebug
	default:
		return slog.LevelWarn
	}
}
