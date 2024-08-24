// Package journalx streams entries from a systemd journal directory.
//
// The problem it solves is narrow. Reading the journal normally means
// linking against libsystemd and calling sd_journal_next, which needs
// cgo. A pure-Go program that wants its host's logs, on a device image
// built with CGO_ENABLED=0, has to parse the journal files itself.
//
// So this package opens a journal directory, reads it from the oldest
// entry it holds, and keeps streaming as new entries are appended:
//
//	j, err := journalx.Open("/var/log/journal/" + machineID)
//	if err != nil {
//		return err
//	}
//	defer j.Close()
//	return j.Follow(ctx, handler)
//
// Follow blocks until ctx is cancelled. Entries arrive as slog.Record
// values, so the destination is any slog.Handler.
//
// # A directory, not a file
//
// A journal is a set of files, not one file. The active system journal
// is system.journal; rotating it renames it to system@<id>-<seq>.journal
// and starts a new one, and a user session gets its own
// user-<uid>.journal with an unrelated sequence. Reading one file means
// missing everything in the others and stopping dead at the first
// rotation.
//
// Open therefore takes the directory. Every *.journal and *.journal~ in
// it is mapped, and their entries are merged into one stream.
//
// # Ordering
//
// Entries carry a sequence number, and the file header carries the
// sequence ID that number belongs to. Within one sequence ID, which a
// journal shares with all of its rotated archives, sequence numbers are
// dense and authoritative, so they order those entries exactly. Across
// sequence IDs, the system journal against a user journal for instance,
// the numbers are unrelated and the only comparable thing is the wall
// clock, so realtime timestamps order them.
//
// # How it follows
//
// Files are mapped read-only and the directory is watched with inotify.
// A write arrives as IN_MODIFY and the mapping is extended over the
// larger file; a rotation arrives as a rename, and a new file as
// IN_CREATE. Between changes the reader blocks in the kernel rather than
// polling, and each wake-up rescans the directory and walks every file
// to its tail.
//
// Watching the directory rather than the files is not a refinement. A
// rotation renames the active file and then creates a replacement, and
// in the window between those the name does not exist, so there is
// nothing for a per-file watch to attach to. Identity is by inode as
// well, because a mapping is bound to an inode rather than to a path:
// after a rotation the name refers to a new file while the old mapping
// still shows the old contents, and two journals holding the same
// entries are the same length, so size cannot tell them apart either.
//
// Because a file is mapped while systemd is still writing to it, an
// object header can be visible before its payload and an entry array
// slot can point past the end of what is currently mapped. Running off
// the written data is therefore normal and means "wait"; a malformed
// object is an error and is returned.
//
// # What it does not do
//
// This is a reader, not a reimplementation of sd_journal. There is no
// cursor, no reverse iteration, no field indexing and no query
// interface; the hash tables are parsed but never consulted. Forward
// Secure Sealing tags are skipped rather than verified, because
// verifying them needs a key this package has no way to obtain. Payloads
// compressed with XZ or LZ4 are rejected with ErrUnsupportedFlags; only
// ZSTD, the current default, is decompressed.
//
// One ordering limitation survives the merge, and systemd names it under
// SD_JOURNAL_INVALIDATE: a file that appears after the stream has
// already moved past its timestamps contributes entries older than ones
// already reported. Following a live journal cannot avoid that without
// buffering indefinitely, so entries are reported in the order they
// become visible, which is the oldest-first order of everything readable
// at the time. A file removed before it was read is simply lost, and a
// file that fails to parse is skipped rather than stopping the stream.
//
// # Field values are not strings
//
// A journal field value is arbitrary binary data. The journal export
// format defines a length-prefixed encoding for exactly this reason, and
// the JSON format serialises such values as arrays of byte values. See
// https://systemd.io/JOURNAL_EXPORT_FORMATS/.
//
// Follow reflects that: a value that is valid UTF-8 becomes a string
// attribute, and anything else is passed through as a []byte for the
// handler to render. A field name may also repeat within one entry, in
// which case the values collect into one attribute holding all of them
// rather than the last one winning.
//
// # Concurrency
//
// A Journal is not safe for concurrent use. Follow owns the whole value
// while it runs, and Close must not be called until it has returned.
// Two readers of the same directory should Open it twice: the kernel
// shares the page cache, so the only duplicated cost is page tables.
package journalx
