//go:build linux

package journalx

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// watchMask is the set of directory events that mean a journal reader
// should look again.
//
// A write to any file in the directory arrives as IN_MODIFY. Rotation is
// a rename within the directory, so it arrives as IN_MOVED_FROM for the
// old name and IN_MOVED_TO or IN_CREATE for the new one. Vacuuming an
// archived file arrives as IN_DELETE.
//
// IN_ACCESS and IN_OPEN are deliberately absent: the reader maps these
// files, so its own reads would otherwise wake it in a loop.
const watchMask = unix.IN_MODIFY |
	unix.IN_CREATE |
	unix.IN_DELETE |
	unix.IN_MOVED_TO |
	unix.IN_MOVED_FROM |
	unix.IN_DELETE_SELF |
	unix.IN_MOVE_SELF

// watcher reports that something in a directory changed.
//
// It is deliberately not exported, and deliberately says nothing about
// what changed. Watching the directory rather than individual files is
// what makes rotation work at all: a rename is followed by the creation
// of a replacement, and in the window between them the new name does not
// exist, so there is no file to attach a watch to. Watching the
// directory also means the watch never has to be re-armed.
//
// Because the reader responds to any change by rescanning the directory
// and draining every file to its tail, a single "something happened"
// signal carries as much information as a parsed event would, and costs
// far less to reason about.
type watcher struct {
	// f owns the inotify descriptor. It is an *os.File rather than a raw
	// descriptor so the runtime poller owns the blocking read: that is
	// what lets Close interrupt a read already in progress. Closing a
	// raw descriptor under a blocked read(2) works too, but races
	// against the descriptor number being reused.
	f  *os.File
	wd int
}

// newWatcher starts watching dir.
func newWatcher(dir string) (*watcher, error) {
	// IN_NONBLOCK is what makes the descriptor pollable, and therefore
	// what makes os.NewFile hand it to the runtime poller rather than
	// falling back to blocking reads.
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("journalx: inotify_init1: %w", err)
	}
	w := &watcher{f: os.NewFile(uintptr(fd), "inotify")}

	wd, err := w.control(func(fd int) (int, error) {
		return unix.InotifyAddWatch(fd, dir, watchMask)
	})
	if err != nil {
		w.Close() //nolint:errcheck
		return nil, fmt.Errorf("journalx: watch %s: %w", dir, err)
	}
	w.wd = wd
	return w, nil
}

// next blocks until something in the watched directory changes.
//
// After Close it returns an error wrapping os.ErrClosed, which is how
// cancellation reaches a reader parked here.
func (w *watcher) next() error {
	// Directory events carry the child's name, so they are variable
	// length. The buffer is sized for a batch rather than one event: a
	// burst of writes then costs a single read.
	var buf [16 * (unix.SizeofInotifyEvent + unix.NAME_MAX + 1)]byte

	for {
		n, err := w.f.Read(buf[:])
		if err != nil {
			return fmt.Errorf("journalx: read inotify: %w", err)
		}
		if actionable(buf[:n]) {
			return nil
		}
		// Everything in this batch was noise. Park again rather than
		// waking the reader for nothing.
	}
}

// actionable reports whether a batch of raw inotify events contains
// anything a journal reader should react to.
//
// The queue overflowing (IN_Q_OVERFLOW) counts, because the events that
// were dropped may have been the ones that mattered and a rescan is the
// recovery. So does the directory itself going away, so the reader can
// notice and report it rather than parking forever.
func actionable(buf []byte) bool {
	for offset := 0; offset+unix.SizeofInotifyEvent <= len(buf); {
		// Read through a pointer rather than decoding field by field,
		// because struct inotify_event is in native byte order, unlike
		// the journal files themselves which are little-endian
		// everywhere.
		e := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		offset += unix.SizeofInotifyEvent + int(e.Len)

		if e.Mask&(watchMask|unix.IN_Q_OVERFLOW|unix.IN_IGNORED) != 0 {
			return true
		}
	}
	return false
}

// control runs fn on the inotify descriptor without taking it away from
// the runtime poller, which is what (*os.File).Fd would do.
func (w *watcher) control(fn func(fd int) (int, error)) (int, error) {
	rc, err := w.f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var res int
	var fnErr error
	if err := rc.Control(func(fd uintptr) {
		res, fnErr = fn(int(fd))
	}); err != nil {
		return 0, err
	}
	return res, fnErr
}

// Close releases the inotify descriptor, unblocking any read in
// progress. It is safe to call more than once, because Follow closes the
// watcher on its way out and the goroutine watching the context may have
// closed it already.
func (w *watcher) Close() error {
	if err := w.f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}
