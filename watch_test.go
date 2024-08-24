//go:build linux

package journalx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// encodeEvents renders masks as the raw inotify buffer the kernel would
// deliver. Built as a typed slice rather than raw bytes so the events
// are aligned for the pointer read that actionable does.
func encodeEvents(masks []uint32) []byte {
	if len(masks) == 0 {
		return nil
	}
	events := make([]unix.InotifyEvent, len(masks))
	for i, mask := range masks {
		events[i] = unix.InotifyEvent{Wd: 1, Mask: mask}
	}
	return unsafe.Slice(
		(*byte)(unsafe.Pointer(&events[0])),
		len(events)*int(unsafe.Sizeof(events[0])),
	)
}

// expectChange asserts that the watcher reports a change, failing the
// test rather than hanging if none arrives.
func expectChange(t *testing.T, w *watcher) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- w.next() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("next: %v", err)
		}
	case <-time.After(failTimeout):
		t.Fatal("timed out waiting for an inotify change")
	}
}

func newTestWatcher(t *testing.T, dir string) *watcher {
	t.Helper()
	w, err := newWatcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("watcher Close: %v", err)
		}
	})
	return w
}

// TestWatcherReportsDirectoryChanges covers each way a journal directory
// changes under a running reader. They are separate subtests rather than
// one sequence because each has to be observed from a fresh watch: a
// single watch would coalesce them.
func TestWatcherReportsDirectoryChanges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// setup runs before the watch is established.
		setup func(t *testing.T, dir string)
		// act runs after, and must produce a change.
		act func(t *testing.T, dir string)
	}{
		{
			// The common case: systemd appending to the active journal.
			name: "file modified",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "system.journal"), "initial")
			},
			act: func(t *testing.T, dir string) {
				appendFile(t, filepath.Join(dir, "system.journal"), " more")
			},
		},
		{
			// The second half of a rotation, and the event a per-file
			// watch could never see because the name did not exist yet.
			name:  "file created",
			setup: func(t *testing.T, dir string) {},
			act: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "system.journal"), "new")
			},
		},
		{
			// The first half of a rotation.
			name: "file renamed away",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "system.journal"), "initial")
			},
			act: func(t *testing.T, dir string) {
				rename(t, filepath.Join(dir, "system.journal"),
					filepath.Join(dir, "system@0001.journal"))
			},
		},
		{
			// Vacuuming an archived file.
			name: "file deleted",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "system@0001.journal"), "old")
			},
			act: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "system@0001.journal")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tt.setup(t, dir)

			w := newTestWatcher(t, dir)
			tt.act(t, dir)
			expectChange(t, w)
		})
	}
}

// TestWatcherSurvivesRotation is the property the previous per-file
// watch could not provide. A rename followed by the creation of a
// replacement is two events with a window between them where the name
// does not exist, so there is nothing to attach a file watch to. The
// directory watch never has to be re-armed and sees both.
func TestWatcherSurvivesRotation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	active := filepath.Join(dir, "system.journal")
	writeFile(t, active, "first")

	w := newTestWatcher(t, dir)

	rename(t, active, filepath.Join(dir, "system@0001.journal"))
	expectChange(t, w)

	writeFile(t, active, "second")
	expectChange(t, w)

	appendFile(t, active, " appended")
	expectChange(t, w)
}

// TestWatcherCloseUnblocksNext is the property Follow relies on for
// cancellation: a blocked read cannot be interrupted with a context, so
// Close has to do it.
func TestWatcherCloseUnblocksNext(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	w, err := newWatcher(dir)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- w.next() }()

	// Close while next is blocked. There is no way to observe that it has
	// reached the read, so the assertion holds either way round: if Close
	// won the race, next returns the same error.
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("next after Close = %v, want an error matching os.ErrClosed", err)
		}
	case <-time.After(failTimeout):
		t.Fatal("Close did not unblock next")
	}
}

// TestWatcherCloseIsIdempotent matters because Follow closes the watcher
// on its way out and the goroutine watching the context may have closed
// it already.
func TestWatcherCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	w, err := newWatcher(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestNewWatcherMissingDirectory checks the error path, since a journal
// directory is absent entirely on a system with no persistent journal.
func TestNewWatcherMissingDirectory(t *testing.T) {
	t.Parallel()
	_, err := newWatcher(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("expected an error watching a missing directory, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want one matching os.ErrNotExist", err)
	}
}

// TestActionable covers the filter applied to a raw event batch. The
// reader responds to any change by rescanning, so the only question is
// whether a batch contains anything at all worth waking for.
func TestActionable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		masks []uint32
		want  bool
	}{
		{"empty batch", nil, false},
		{"modify", []uint32{unix.IN_MODIFY}, true},
		{"create", []uint32{unix.IN_CREATE}, true},
		{"delete", []uint32{unix.IN_DELETE}, true},
		{"moved to", []uint32{unix.IN_MOVED_TO}, true},
		{"moved from", []uint32{unix.IN_MOVED_FROM}, true},
		{"directory itself moved", []uint32{unix.IN_MOVE_SELF}, true},
		{"directory itself deleted", []uint32{unix.IN_DELETE_SELF}, true},

		// The kernel dropped events. A rescan is the recovery, so this
		// has to wake the reader even though it names nothing.
		{"queue overflow", []uint32{unix.IN_Q_OVERFLOW}, true},

		// The watch went away, which the reader must notice rather than
		// park on forever.
		{"watch removed", []uint32{unix.IN_IGNORED}, true},

		// Reads are the reader's own doing and must not wake it.
		{"open and access ignored", []uint32{unix.IN_OPEN, unix.IN_ACCESS}, false},
		{"access then modify", []uint32{unix.IN_ACCESS, unix.IN_MODIFY}, true},
		{"batch of modifies", []uint32{unix.IN_MODIFY, unix.IN_MODIFY}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := actionable(encodeEvents(tt.masks)); got != tt.want {
				t.Errorf("actionable = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- file helpers ------------------------------------------------------------

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close() //nolint:errcheck
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func rename(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}
