//go:build linux

package journalx

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenerate the journal files under testdata")

// failTimeout bounds every wait in this file. It exists to fail a test
// that would otherwise hang, never to give something time to happen: the
// tests wait on records arriving, not on the clock.
const failTimeout = 30 * time.Second

// --- record collection -------------------------------------------------------

// record is a comparable projection of an slog.Record. Only what the
// reader is responsible for producing is captured.
type record struct {
	Realtime time.Time
	Level    slog.Level
	Message  string
	Attrs    map[string]any
}

// collector is an slog.Handler that accumulates records and lets a test
// block until a given number of them have arrived.
//
// It is the seam that makes these tests wait for the real event instead
// of for a duration. Follow blocks in the kernel until the file changes,
// so a test appends entries and then waits here; deleting the wait would
// make the test fail rather than flake.
type collector struct {
	mu      sync.Mutex
	records []record

	// changed is closed and replaced on every record, so any number of
	// waiters can be woken without knowing the target count in advance.
	changed chan struct{}
}

func newCollector() *collector {
	return &collector{changed: make(chan struct{})}
}

func (c *collector) Enabled(context.Context, slog.Level) bool { return true }

func (c *collector) WithAttrs([]slog.Attr) slog.Handler { return c }

func (c *collector) WithGroup(string) slog.Handler { return c }

func (c *collector) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})

	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record{
		Realtime: r.Time,
		Level:    r.Level,
		Message:  r.Message,
		Attrs:    attrs,
	})
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}

// got returns a copy of the records collected so far.
func (c *collector) got() []record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.records)
}

// waitFor blocks until at least n records have arrived.
//
// It also watches the running Follow, so a reader that returned early
// fails the test with its own error rather than as a timeout thirty
// seconds later. Diagnosing "timed out waiting for 2 records" is much
// harder than reading the error Follow actually produced.
func (c *collector) waitFor(t *testing.T, n int, f *follower) {
	t.Helper()
	deadline := time.After(failTimeout)
	for {
		c.mu.Lock()
		have := len(c.records)
		changed := c.changed
		c.mu.Unlock()

		if have >= n {
			return
		}
		select {
		case <-changed:
		case err := <-f.done:
			f.returned = true
			t.Fatalf("Follow returned early with %d of %d records: %v", have, n, err)
		case <-deadline:
			t.Fatalf("timed out waiting for %d records, have %d", n, have)
		}
	}
}

// --- golden corpus -----------------------------------------------------------

// goldenCase is one committed journal directory and the records reading
// it must produce.
//
// A directory rather than a file because that is what Open takes, and
// because the interesting cases are about how several files combine. The
// bytes are committed so the whole read path is testable with no systemd
// on the host: a container, CI, and a laptop all read the same files.
// build is what regenerates them.
type goldenCase struct {
	name string

	// build returns the files to write, keyed by base name.
	build func(t *testing.T) map[string]*builder

	want []record
}

// entryTime returns the timestamp the builder assigns to the nth entry,
// counting from one. Kept in one place so the expectations below read as
// data rather than arithmetic.
func entryTime(n int) time.Time {
	return time.UnixMicro(1700000000_000000 + int64(n)*1_000_000)
}

// oneFile is the common shape: a directory holding just the active
// system journal.
func oneFile(b *builder) map[string]*builder {
	return map[string]*builder{"system.journal": b}
}

func goldenCases() []goldenCase {
	return []goldenCase{
		{
			// The ordinary case: a few entries with plain text fields,
			// one entry array, no compression.
			name: "simple",
			build: func(t *testing.T) map[string]*builder {
				b := newBuilder(t)
				b.addEntry(fields{{"MESSAGE", "first"}, {"PRIORITY", "6"}, {"_PID", "1"}})
				b.addEntry(fields{{"MESSAGE", "second"}, {"PRIORITY", "3"}, {"_PID", "2"}})
				b.addEntry(fields{{"MESSAGE", "third"}, {"PRIORITY", "7"}, {"_PID", "3"}})
				return oneFile(b)
			},
			want: []record{
				{entryTime(1), slog.LevelInfo, "first", map[string]any{"_PID": "1"}},
				{entryTime(2), slog.LevelError, "second", map[string]any{"_PID": "2"}},
				{entryTime(3), slog.LevelDebug, "third", map[string]any{"_PID": "3"}},
			},
		},
		{
			// Compact mode: 32-bit object offsets and the extra le32 pair
			// in every data object. Default since systemd v252.
			name: "compact",
			build: func(t *testing.T) map[string]*builder {
				b := newBuilder(t, withCompact())
				b.addEntry(fields{{"MESSAGE", "compact one"}, {"PRIORITY", "6"}})
				b.addEntry(fields{{"MESSAGE", "compact two"}, {"PRIORITY", "4"}})
				return oneFile(b)
			},
			want: []record{
				{entryTime(1), slog.LevelInfo, "compact one", map[string]any{}},
				{entryTime(2), slog.LevelWarn, "compact two", map[string]any{}},
			},
		},
		{
			// Every payload ZSTD compressed, which is what systemd does
			// once a field exceeds its compression threshold.
			name: "zstd",
			build: func(t *testing.T) map[string]*builder {
				b := newBuilder(t, withCompact(), withZSTD())
				b.addEntry(fields{
					{"MESSAGE", strings.Repeat("compressible ", 32)},
					{"PRIORITY", "6"},
				})
				return oneFile(b)
			},
			want: []record{
				{entryTime(1), slog.LevelInfo, strings.Repeat("compressible ", 32), map[string]any{}},
			},
		},
		{
			// The cases the export format exists to describe: a value
			// holding a newline, a value that is not valid UTF-8, and a
			// field name repeated within one entry.
			name: "binary-fields",
			build: func(t *testing.T) map[string]*builder {
				b := newBuilder(t)
				b.addEntry(fields{
					{"MESSAGE", "multi\nline"},
					{"PRIORITY", "6"},
					{"BINARY", "\xff\xfe\x00raw"},
					{"_UDEV_DEVLINK", "/dev/alias1"},
					{"_UDEV_DEVLINK", "/dev/alias2"},
				})
				return oneFile(b)
			},
			want: []record{
				{
					entryTime(1), slog.LevelInfo, "multi\nline",
					map[string]any{
						"BINARY":        []byte("\xff\xfe\x00raw"),
						"_UDEV_DEVLINK": []any{"/dev/alias1", "/dev/alias2"},
					},
				},
			},
		},
		{
			// Five entries into arrays of two, so the reader has to
			// follow the entry array chain twice.
			name: "chained-arrays",
			build: func(t *testing.T) map[string]*builder {
				b := newBuilder(t, withArrayCap(2))
				for i := 1; i <= 5; i++ {
					b.addEntry(fields{
						{"MESSAGE", fmt.Sprintf("entry %d", i)},
						{"PRIORITY", "6"},
					})
				}
				return oneFile(b)
			},
			want: []record{
				{entryTime(1), slog.LevelInfo, "entry 1", map[string]any{}},
				{entryTime(2), slog.LevelInfo, "entry 2", map[string]any{}},
				{entryTime(3), slog.LevelInfo, "entry 3", map[string]any{}},
				{entryTime(4), slog.LevelInfo, "entry 4", map[string]any{}},
				{entryTime(5), slog.LevelInfo, "entry 5", map[string]any{}},
			},
		},
		{
			// No PRIORITY field. Reported at Warn so a handler filtering
			// at Info does not drop it silently.
			name: "no-priority",
			build: func(t *testing.T) map[string]*builder {
				b := newBuilder(t)
				b.addEntry(fields{{"MESSAGE", "unprioritised"}})
				return oneFile(b)
			},
			want: []record{
				{entryTime(1), slog.LevelWarn, "unprioritised", map[string]any{}},
			},
		},
		{
			// A journal and its rotated archive. Same sequence ID, so the
			// two files are one stream and sequence numbers order it
			// exactly. The archive sorts first by name, but that is
			// incidental: the merge must use sequence numbers, not names.
			name: "rotated",
			build: func(t *testing.T) map[string]*builder {
				archived := newBuilder(t)
				archived.addEntry(fields{{"MESSAGE", "archived one"}, {"PRIORITY", "6"}})
				archived.addEntry(fields{{"MESSAGE", "archived two"}, {"PRIORITY", "6"}})

				// Continues the same sequence, as a rotated journal does.
				active := newBuilder(t, withStart(2, baseRealtime+2*entryInterval))
				active.addEntry(fields{{"MESSAGE", "active one"}, {"PRIORITY", "4"}})
				active.addEntry(fields{{"MESSAGE", "active two"}, {"PRIORITY", "3"}})

				return map[string]*builder{
					"system@0001.journal": archived,
					"system.journal":      active,
				}
			},
			want: []record{
				{entryTime(1), slog.LevelInfo, "archived one", map[string]any{}},
				{entryTime(2), slog.LevelInfo, "archived two", map[string]any{}},
				{entryTime(3), slog.LevelWarn, "active one", map[string]any{}},
				{entryTime(4), slog.LevelError, "active two", map[string]any{}},
			},
		},
		{
			// A system journal and a user journal: different sequence
			// IDs, so their sequence numbers are unrelated and the only
			// comparable thing is the wall clock. Timestamps interleave,
			// and the expected order is by time rather than by file.
			name: "interleaved",
			build: func(t *testing.T) map[string]*builder {
				// Entries at t+1 and t+3.
				system := newBuilder(t, withSeqnumID(0x44))
				system.addEntry(fields{{"MESSAGE", "system at 1"}, {"PRIORITY", "6"}})
				system.realtime += entryInterval
				system.addEntry(fields{{"MESSAGE", "system at 3"}, {"PRIORITY", "6"}})

				// Entries at t+2 and t+4, from an unrelated journal whose
				// sequence numbers restart at one.
				user := newBuilder(t, withSeqnumID(0x55),
					withStart(0, baseRealtime+entryInterval))
				user.addEntry(fields{{"MESSAGE", "user at 2"}, {"PRIORITY", "6"}})
				user.realtime += entryInterval
				user.addEntry(fields{{"MESSAGE", "user at 4"}, {"PRIORITY", "6"}})

				return map[string]*builder{
					"system.journal":    system,
					"user-1000.journal": user,
				}
			},
			want: []record{
				{entryTime(1), slog.LevelInfo, "system at 1", map[string]any{}},
				{entryTime(2), slog.LevelInfo, "user at 2", map[string]any{}},
				{entryTime(3), slog.LevelInfo, "system at 3", map[string]any{}},
				{entryTime(4), slog.LevelInfo, "user at 4", map[string]any{}},
			},
		},
	}
}

// goldenDir is the committed directory for a case.
func goldenDir(name string) string {
	return filepath.Join("testdata", name)
}

// TestGoldenFiles verifies that the committed fixtures still match what
// the builder produces, and rewrites them under -update.
//
// This is the repository's usual shape for generated output: the bytes
// are committed so a fresh clone can run the suite, and a plain run
// fails if they have drifted.
func TestGoldenFiles(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			dir := goldenDir(tc.name)
			files := tc.build(t)

			if *update {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				// Remove files a previous corpus wrote but this one no
				// longer produces, so a renamed case cannot leave a
				// stale file behind that Open would still read.
				stale, err := journalFileNames(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range stale {
					if _, want := files[name]; !want {
						if err := os.Remove(filepath.Join(dir, name)); err != nil {
							t.Fatal(err)
						}
					}
				}
				for name, b := range files {
					path := filepath.Join(dir, name)
					if err := os.WriteFile(path, b.bytes(), 0o644); err != nil {
						t.Fatal(err)
					}
					t.Logf("wrote %s", path)
				}
				return
			}

			for _, name := range slices.Sorted(maps.Keys(files)) {
				path := filepath.Join(dir, name)
				want := files[name].bytes()
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("%v; regenerate with: go test ./journalx/ -update", err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s differs from the builder at byte %d of %d; regenerate with: go test ./journalx/ -update",
						path, firstDifference(got, want), len(want))
				}
			}
		})
	}
}

// firstDifference reports where two byte slices diverge, which is far
// more useful in a failure message than "they differ".
func firstDifference(got, want []byte) int {
	for i := range min(len(got), len(want)) {
		if got[i] != want[i] {
			return i
		}
	}
	return min(len(got), len(want))
}

// TestGoldenEntries reads each committed fixture and checks the records
// it produces. This is the core correctness test for the read path and
// it needs nothing from the host.
func TestGoldenEntries(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j := openGolden(t, tc.name)

			got := drainAll(t, j)
			assertRecords(t, got, tc.want)
		})
	}
}

// TestGoldenEntriesViaFollow runs the same fixtures through Follow, so
// the inotify and cancellation path is covered too, not just drain.
func TestGoldenEntriesViaFollow(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j := openGolden(t, tc.name)

			c := newCollector()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			done := followInBackground(t, j, ctx, c)
			c.waitFor(t, len(tc.want), done)
			cancel()
			waitForFollow(t, done)

			assertRecords(t, c.got(), tc.want)
		})
	}
}

// TestFollowGrowth covers a file being appended to while it is followed.
//
// The mapping has to be extended over the larger file, and the entry
// offsets are written into slots of an entry array the reader already
// walked past, so it has to look at that array again rather than assume
// it is finished with it.
func TestFollowGrowth(t *testing.T) {
	dir := t.TempDir()

	b := newBuilder(t, withArrayCap(8))
	b.addEntry(fields{{"MESSAGE", "before follow"}, {"PRIORITY", "6"}})
	b.write(filepath.Join(dir, "system.journal"))

	j := openDir(t, dir)
	c := newCollector()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := followInBackground(t, j, ctx, c)

	// Waiting for the pre-existing entry first is what makes the append
	// below a growth event rather than part of the initial drain.
	c.waitFor(t, 1, done)

	b.appendEntry(fields{{"MESSAGE", "after follow"}, {"PRIORITY", "3"}})
	c.waitFor(t, 2, done)

	b.appendEntry(fields{{"MESSAGE", "later still"}, {"PRIORITY", "7"}})
	c.waitFor(t, 3, done)

	cancel()
	waitForFollow(t, done)

	assertRecords(t, c.got(), []record{
		{entryTime(1), slog.LevelInfo, "before follow", map[string]any{}},
		{entryTime(2), slog.LevelError, "after follow", map[string]any{}},
		{entryTime(3), slog.LevelDebug, "later still", map[string]any{}},
	})
}

// TestFollowRotation covers rotation as systemd performs it: the active
// file is renamed to an archive name and a fresh file takes its place.
//
// This is the case a per-file watch could not handle. The rename and the
// creation of the replacement are separate operations, and in the window
// between them the name does not exist, so there is no file to attach a
// watch to and reopening by name fails with ENOENT. Watching the
// directory removes the window: the reader learns when the replacement
// appears.
func TestFollowRotation(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "system.journal")

	first := newBuilder(t, withArrayCap(8))
	first.addEntry(fields{{"MESSAGE", "before rotation"}, {"PRIORITY", "6"}})
	first.write(active)

	j := openDir(t, dir)
	c := newCollector()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := followInBackground(t, j, ctx, c)

	c.waitFor(t, 1, done)

	// Rotate: rename the active file away, then put a new one in its
	// place. Deliberately two steps with no synchronisation between
	// them, because that is what systemd does and the gap is the whole
	// point of the test.
	if err := os.Rename(active, filepath.Join(dir, "system@0001.journal")); err != nil {
		t.Fatal(err)
	}

	second := newBuilder(t, withArrayCap(8),
		withStart(first.seqnum, first.realtime))
	second.addEntry(fields{{"MESSAGE", "after rotation"}, {"PRIORITY", "4"}})
	second.write(active)

	c.waitFor(t, 2, done)

	// A further append to the replacement proves the reader is following
	// the new file and not still parked on the renamed one.
	second.appendEntry(fields{{"MESSAGE", "after rotation twice"}, {"PRIORITY", "6"}})
	c.waitFor(t, 3, done)

	cancel()
	waitForFollow(t, done)

	assertRecords(t, c.got(), []record{
		{entryTime(1), slog.LevelInfo, "before rotation", map[string]any{}},
		{entryTime(2), slog.LevelWarn, "after rotation", map[string]any{}},
		{entryTime(3), slog.LevelInfo, "after rotation twice", map[string]any{}},
	})
}

// TestFollowNewFileAppears covers a journal directory that gains a file
// while it is being read, which is what happens when a user logs in and
// systemd starts a user journal, and when the very first journal file is
// created in an empty directory.
func TestFollowNewFileAppears(t *testing.T) {
	dir := t.TempDir()

	system := newBuilder(t, withArrayCap(8), withSeqnumID(0x44))
	system.addEntry(fields{{"MESSAGE", "system first"}, {"PRIORITY", "6"}})
	system.write(filepath.Join(dir, "system.journal"))

	j := openDir(t, dir)
	c := newCollector()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := followInBackground(t, j, ctx, c)

	c.waitFor(t, 1, done)

	// An unrelated journal, so ordering against the system journal falls
	// back to the wall clock.
	user := newBuilder(t, withArrayCap(8), withSeqnumID(0x55),
		withStart(0, baseRealtime+entryInterval))
	user.addEntry(fields{{"MESSAGE", "user first"}, {"PRIORITY", "6"}})
	user.write(filepath.Join(dir, "user-1000.journal"))

	c.waitFor(t, 2, done)

	cancel()
	waitForFollow(t, done)

	assertRecords(t, c.got(), []record{
		{entryTime(1), slog.LevelInfo, "system first", map[string]any{}},
		{entryTime(2), slog.LevelInfo, "user first", map[string]any{}},
	})
}

// TestFollowEmptyDirectory covers starting before systemd has written
// anything. Open must succeed on an empty journal directory, and Follow
// must wait rather than conclude there is nothing to read.
func TestFollowEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	j := openDir(t, dir)
	c := newCollector()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := followInBackground(t, j, ctx, c)

	b := newBuilder(t, withArrayCap(8))
	b.addEntry(fields{{"MESSAGE", "the first entry ever"}, {"PRIORITY", "6"}})
	b.write(filepath.Join(dir, "system.journal"))

	c.waitFor(t, 1, done)
	cancel()
	waitForFollow(t, done)

	assertRecords(t, c.got(), []record{
		{entryTime(1), slog.LevelInfo, "the first entry ever", map[string]any{}},
	})
}

// TestFollowVacuumedFile covers systemd deleting an archived file while
// the reader has it open. The entries in it have already been reported,
// so the reader should drop the file and carry on rather than fail.
func TestFollowVacuumedFile(t *testing.T) {
	dir := t.TempDir()
	archived := filepath.Join(dir, "system@0001.journal")

	old := newBuilder(t, withArrayCap(8))
	old.addEntry(fields{{"MESSAGE", "archived"}, {"PRIORITY", "6"}})
	old.write(archived)

	active := newBuilder(t, withArrayCap(8), withStart(1, baseRealtime+entryInterval))
	active.addEntry(fields{{"MESSAGE", "active"}, {"PRIORITY", "6"}})
	active.write(filepath.Join(dir, "system.journal"))

	j := openDir(t, dir)
	c := newCollector()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := followInBackground(t, j, ctx, c)

	c.waitFor(t, 2, done)

	if err := os.Remove(archived); err != nil {
		t.Fatal(err)
	}

	// The reader must still be working afterwards.
	active.appendEntry(fields{{"MESSAGE", "after vacuum"}, {"PRIORITY", "6"}})
	c.waitFor(t, 3, done)

	cancel()
	waitForFollow(t, done)

	if got := len(j.files); got != 1 {
		t.Errorf("%d files open after the vacuum, want 1", got)
	}
	assertRecords(t, c.got(), []record{
		{entryTime(1), slog.LevelInfo, "archived", map[string]any{}},
		{entryTime(2), slog.LevelInfo, "active", map[string]any{}},
		{entryTime(3), slog.LevelInfo, "after vacuum", map[string]any{}},
	})
}

// TestFollowReturnsOnCancel is the lifecycle test. Follow used to spawn
// a goroutine nobody could wait for, which unmapped the file on
// cancellation while the reader might still be parsing it. Follow must
// now return by itself, leaving nothing running behind it.
func TestFollowReturnsOnCancel(t *testing.T) {
	t.Parallel()
	j := openGolden(t, "simple")

	c := newCollector()
	ctx, cancel := context.WithCancel(t.Context())
	done := followInBackground(t, j, ctx, c)

	// Cancel only once the reader is demonstrably blocked waiting for a
	// change, which is the state the old code got wrong.
	c.waitFor(t, 3, done)
	cancel()
	waitForFollow(t, done)

	// The mappings must still be intact: Follow no longer owns them, so
	// reading after cancellation is valid rather than a use-after-unmap.
	if len(j.files) == 0 {
		t.Fatal("no files open after Follow returned")
	}
	for name, f := range j.files {
		if _, err := f.arrayAt(f.h.EntryArrayOffset); err != nil {
			t.Errorf("%s unreadable after Follow returned: %v", name, err)
		}
	}
}

// --- helpers -----------------------------------------------------------------

// openGolden opens a committed fixture directory and closes it when the
// test ends.
func openGolden(t *testing.T, name string) *Journal {
	t.Helper()
	j, err := Open(goldenDir(name))
	if err != nil {
		t.Fatalf("Open(%s): %v; regenerate with: go test ./journalx/ -update",
			goldenDir(name), err)
	}
	registerClose(t, j)
	return j
}

// openDir opens a journal directory written by a test.
func openDir(t *testing.T, dir string) *Journal {
	t.Helper()
	j, err := Open(dir)
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	registerClose(t, j)
	return j
}

// registerClose closes j when the test ends. Errorf rather than Fatalf,
// because a cleanup that calls runtime.Goexit abandons the cleanups
// registered before it.
func registerClose(t *testing.T, j *Journal) {
	t.Helper()
	t.Cleanup(func() {
		if err := j.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
}

// drainAll reads everything currently in the journal, without inotify.
func drainAll(t *testing.T, j *Journal) []record {
	t.Helper()
	c := newCollector()
	if err := j.drain(t.Context(), c); err != nil {
		t.Fatalf("drain: %v", err)
	}
	return c.got()
}

// follower is a Follow running in the background.
type follower struct {
	done chan error

	// cancel stops it. Held here so the cleanup can stop a Follow the
	// test abandoned by failing.
	cancel context.CancelFunc

	// returned records that the result was already consumed, so nothing
	// waits on a channel that will not be sent to again.
	returned bool
}

// followInBackground starts Follow.
//
// The cleanup it registers is what keeps a Journal single-reader even
// when a test fails: t.Fatalf runs cleanups, and without this one the
// Journal would be closed by openDir's cleanup while Follow was still
// using it. Registration order does the work, since this runs after
// openDir and cleanups run last-registered-first.
func followInBackground(t *testing.T, j *Journal, ctx context.Context, h slog.Handler) *follower {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	f := &follower{done: make(chan error, 1), cancel: cancel}
	go func() { f.done <- j.Follow(ctx, h) }()
	t.Cleanup(func() {
		if f.returned {
			return
		}
		f.cancel()
		select {
		case <-f.done:
		case <-time.After(failTimeout):
			t.Error("Follow did not return; the journal is still in use")
		}
	})
	return f
}

// waitForFollow asserts that Follow returned cleanly.
func waitForFollow(t *testing.T, f *follower) {
	t.Helper()
	if f.returned {
		return
	}
	select {
	case err := <-f.done:
		f.returned = true
		if err != nil {
			t.Errorf("Follow: %v", err)
		}
	case <-time.After(failTimeout):
		t.Fatal("timed out waiting for Follow to return after cancellation")
	}
}

// assertRecords compares collected records against expectations.
func assertRecords(t *testing.T, got, want []record) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d:\n got: %s\nwant: %s",
			len(got), len(want), formatRecords(got), formatRecords(want))
	}
	for i := range want {
		if !recordsEqual(got[i], want[i]) {
			t.Errorf("record %d:\n got: %s\nwant: %s", i,
				formatRecord(got[i]), formatRecord(want[i]))
		}
	}
}

func recordsEqual(a, b record) bool {
	if !a.Realtime.Equal(b.Realtime) || a.Level != b.Level || a.Message != b.Message {
		return false
	}
	if len(a.Attrs) != len(b.Attrs) {
		return false
	}
	for k, av := range a.Attrs {
		bv, ok := b.Attrs[k]
		if !ok || fmt.Sprintf("%#v", av) != fmt.Sprintf("%#v", bv) {
			return false
		}
	}
	return true
}

func formatRecords(rs []record) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = formatRecord(r)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatRecord(r record) string {
	keys := slices.Sorted(maps.Keys(r.Attrs))
	attrs := make([]string, len(keys))
	for i, k := range keys {
		attrs[i] = fmt.Sprintf("%s=%#v", k, r.Attrs[k])
	}
	return fmt.Sprintf("{%s %s %q {%s}}",
		r.Realtime.UTC().Format(time.RFC3339), r.Level, r.Message, strings.Join(attrs, " "))
}

// --- Open errors -------------------------------------------------------------

// good writes a journal file that parses.
func good(t *testing.T) []byte {
	t.Helper()
	b := newBuilder(t)
	b.addEntry(fields{{"MESSAGE", "readable"}, {"PRIORITY", "6"}})
	return b.bytes()
}

// xz writes a journal file claiming XZ compression, which this reader
// rejects because it has no XZ decompressor.
func xz(t *testing.T) []byte {
	t.Helper()
	b := newBuilder(t)
	b.addEntry(fields{{"MESSAGE", "x"}})
	out := b.bytes()
	// The incompatible flags sit at offset 12: eight bytes of signature
	// then the four compatible flag bytes.
	out[12] = byte(incompatibleCompressedXZ)
	return out
}

// TestOpenDirectory covers Open's contract on a directory, which is
// mostly about what it tolerates rather than what it rejects.
func TestOpenDirectory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// files to write into the directory, keyed by base name.
		files map[string]func(t *testing.T) []byte

		// path replaces the directory passed to Open, for the cases that
		// are about the path itself rather than its contents.
		path func(t *testing.T) string

		// wantFail says Open must return an error, and wantErr what it
		// must match when the identity matters.
		wantFail bool
		wantErr  error

		// wantOpen is how many journal files a successful Open ends up
		// holding.
		wantOpen int
	}{
		{
			// An empty directory is the normal state before systemd has
			// written anything, so it must not be an error: Follow waits.
			name:     "empty directory",
			wantOpen: 0,
		},
		{
			name:     "one readable file",
			files:    map[string]func(*testing.T) []byte{"system.journal": good},
			wantOpen: 1,
		},
		{
			// The point of skipping rather than failing: one unclean file
			// must not stop the others being read.
			name: "unreadable file is skipped",
			files: map[string]func(*testing.T) []byte{
				"system.journal":      good,
				"system@0001.journal": xz,
			},
			wantOpen: 1,
		},
		{
			// Nothing readable is a failure, and the reason has to
			// survive rather than being reduced to a count.
			name:     "nothing readable reports why",
			files:    map[string]func(*testing.T) []byte{"system.journal": xz},
			wantFail: true,
			wantErr:  ErrUnsupportedFlags,
		},
		{
			// Long enough to hold a header, so it is the signature check
			// that rejects it rather than running out of bytes.
			name: "file that is not a journal",
			files: map[string]func(*testing.T) []byte{
				"system.journal": func(*testing.T) []byte {
					return bytes.Repeat([]byte("not a journal!! "), int(headerSize)/16)
				},
			},
			wantFail: true,
			wantErr:  ErrCorrupt,
		},
		{
			// Shorter than a header. Reported as a truncated read rather
			// than as corruption, because a file systemd has created but
			// not yet written a header into looks exactly like this.
			name: "file shorter than a header",
			files: map[string]func(*testing.T) []byte{
				"system.journal": func(*testing.T) []byte { return []byte(journalSignature) },
			},
			wantFail: true,
			wantErr:  io.ErrUnexpectedEOF,
		},
		{
			name: "empty file",
			files: map[string]func(*testing.T) []byte{
				"system.journal": func(*testing.T) []byte { return nil },
			},
			wantFail: true,
		},
		{
			// Files without a journal suffix are not journal files, so
			// other things in the directory are invisible rather than an
			// error. systemd itself keeps the sealing key here as "fss".
			name: "non-journal names ignored",
			files: map[string]func(*testing.T) []byte{
				"system.journal": good,
				"README":         func(*testing.T) []byte { return []byte("notes") },
				"fss":            func(*testing.T) []byte { return []byte("sealing key") },
			},
			wantOpen: 1,
		},
		{
			name:     "empty path",
			path:     func(*testing.T) string { return "" },
			wantFail: true,
		},
		{
			name:     "missing directory",
			path:     func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") },
			wantFail: true,
			wantErr:  os.ErrNotExist,
		},
		{
			// Open takes a directory now, so being handed a journal file
			// has to fail rather than half-work.
			name: "path is a file",
			path: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "system.journal")
				writeFile(t, path, "not a directory")
				return path
			},
			wantFail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			for name, content := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), content(t), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.path != nil {
				dir = tt.path(t)
			}

			j, err := Open(dir)
			if tt.wantFail {
				if err == nil {
					j.Close() //nolint:errcheck
					t.Fatal("expected an error, got nil")
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want one matching %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			registerClose(t, j)
			if got := len(j.files); got != tt.wantOpen {
				t.Errorf("%d files open, want %d", got, tt.wantOpen)
			}
		})
	}
}

// TestCloseIsIdempotent matters because Follow used to unmap the file on
// cancellation while the caller also called Close, which was a double
// munmap.
func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	j := openGolden(t, "simple")
	if err := j.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// --- host journal ------------------------------------------------------------

// TestFollowHostJournal points the reader at the machine's real journal.
//
// It is skipped unless JOURNALX_HOST_TEST is set, because it needs
// systemd, a readable journal directory, and entries actually arriving.
// It is the only test that proves the golden fixtures resemble what
// systemd writes, so it is worth running by hand on a real host:
//
//	JOURNALX_HOST_TEST=1 go test ./journalx/ -run HostJournal -v
func TestFollowHostJournal(t *testing.T) {
	if os.Getenv("JOURNALX_HOST_TEST") == "" {
		t.Skip("set JOURNALX_HOST_TEST=1 to read the host journal")
	}

	file := hostJournalFile()
	if file == "" {
		t.Skip("no /etc/machine-id: not a systemd host")
	}
	if _, err := os.Stat(file); err != nil {
		t.Skipf("no journal at %s: %v", file, err)
	}
	t.Logf("reading %s", file)

	j, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close() //nolint:errcheck

	c := newCollector()
	ctx, cancel := context.WithTimeout(t.Context(), failTimeout)
	defer cancel()

	done := followInBackground(t, j, ctx, c)
	c.waitFor(t, 1, done)
	cancel()
	waitForFollow(t, done)

	got := c.got()
	t.Logf("read %d entries, first: %s", len(got), formatRecord(got[0]))
}

func hostJournalFile() string {
	b, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return ""
	}
	return path.Join("/var/log/journal", id, "system.journal")
}
