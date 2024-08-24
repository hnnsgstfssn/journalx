//go:build linux

package journalx

import (
	"bytes"
	"strings"
	"testing"
)

// TestDumpHeader exercises the header dump.
//
// The dump is deliberately not exported, so nothing in the read path
// calls it and this test is the only thing that does. That is the point:
// without it the dump would be unreferenced code claiming to describe
// the format, and the next person to touch the header struct would have
// no way to know it still worked.
func TestDumpHeader(t *testing.T) {
	t.Parallel()

	b := newBuilder(t, withCompact(), withZSTD())
	b.addEntry(fields{{"MESSAGE", "one"}, {"PRIORITY", "6"}})
	b.addEntry(fields{{"MESSAGE", "two"}, {"PRIORITY", "6"}})

	f := &journalFile{path: "/var/log/journal/test/system.journal"}
	f.buf = b.bytes()
	f.r = bytes.NewReader(f.buf)
	if err := f.readHeader(); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	if err := dumpHeader(&out, f.path, f.h); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	// Checked as substrings rather than against a golden block because
	// the value is the diagnostic content, not the layout, and pinning
	// the layout would make every cosmetic change a test failure.
	want := []string{
		"File path:               /var/log/journal/test/system.journal",
		"State:                   ONLINE",
		"Machine ID:              22222222222222222222222222222222",
		"Sequential number ID:    44444444444444444444444444444444",
		"Compatible flags:        TAIL_ENTRY_BOOT_ID",
		"Incompatible flags:      COMPRESSED-ZSTD COMPACT",
		"Head sequential number:  1",
		"Tail sequential number:  2",
		"Entry objects:           2",

		// 64 buckets, which is what the builder sizes both tables to.
		"Data hash table size:    64",
		"Field hash table size:   64",
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("dump is missing %q\ngot:\n%s", w, got)
		}
	}
}

// TestFlagNames covers the flag decoding the dump relies on, including
// the bits this reader does not support and the unknown ones, since a
// file it refuses to read is exactly when someone reaches for the dump.
func TestFlagNames(t *testing.T) {
	t.Parallel()

	t.Run("incompatible", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name  string
			flags uint32
			want  string
		}{
			{"none", 0, ""},
			{"zstd", incompatibleCompressedZSTD, "COMPRESSED-ZSTD"},
			{"xz", incompatibleCompressedXZ, "COMPRESSED-XZ"},
			{"lz4", incompatibleCompressedLZ4, "COMPRESSED-LZ4"},
			{"keyed hash", incompatibleKeyedHash, "KEYED-HASH"},
			{"compact", incompatibleCompact, "COMPACT"},
			{
				"modern default",
				incompatibleKeyedHash | incompatibleCompressedZSTD | incompatibleCompact,
				"KEYED-HASH COMPRESSED-ZSTD COMPACT",
			},
			{"unknown bit is shown as hex", 1 << 6, "0x40"},
			{"known and unknown", incompatibleCompact | 1<<7, "COMPACT 0x80"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				got := strings.Join(incompatibleFlagNames(tt.flags), " ")
				if got != tt.want {
					t.Errorf("names = %q, want %q", got, tt.want)
				}
			})
		}
	})

	t.Run("compatible", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name  string
			flags uint32
			want  string
		}{
			{"none", 0, ""},
			{"sealed", compatibleSealed, "SEALED"},
			{"tail entry boot id", compatibleTailEntryBootID, "TAIL_ENTRY_BOOT_ID"},
			{"both", compatibleSealed | compatibleTailEntryBootID, "SEALED TAIL_ENTRY_BOOT_ID"},
			{"unknown bit is shown as hex", 1 << 5, "0x20"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				got := strings.Join(compatibleFlagNames(tt.flags), " ")
				if got != tt.want {
					t.Errorf("names = %q, want %q", got, tt.want)
				}
			})
		}
	})
}

func TestStateString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		state uint8
		want  string
	}{
		{stateOffline, "OFFLINE"},
		{stateOnline, "ONLINE"},
		{stateArchived, "ARCHIVED"},
		{stateMax, "UNKNOWN(3)"},
		{99, "UNKNOWN(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := stateString(tt.state); got != tt.want {
				t.Errorf("stateString(%d) = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}
