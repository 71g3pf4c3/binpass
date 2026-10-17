package importer

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// shrinkImportCap lowers the import bound for the duration of a test, so that
// the oversize case can be proven without generating hundreds of megabytes.
func shrinkImportCap(t *testing.T, max int64) {
	t.Helper()
	old := maxImportBytes
	maxImportBytes = max
	t.Cleanup(func() { maxImportBytes = old })
}

// TestLimitReaderRejectsOversizeInput covers the memory-exhaustion case: an
// import file is untrusted input, and every decoder here buffers it. The
// reader must fail instead of reporting EOF, because a decoder handed a
// truncated file imports half a store and calls it a success.
func TestLimitReaderRejectsOversizeInput(t *testing.T) {
	tests := []struct {
		name    string
		max     int64
		input   int
		wantErr bool
	}{
		{name: "under the bound", max: 64, input: 10},
		{name: "exactly at the bound", max: 64, input: 64},
		{name: "one byte over", max: 64, input: 65, wantErr: true},
		{name: "far over", max: 64, input: 4096, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shrinkImportCap(t, tt.max)
			data := bytes.Repeat([]byte("a"), tt.input)
			got, err := io.ReadAll(limitReader(bytes.NewReader(data)))
			if tt.wantErr {
				if !errors.Is(err, ErrTooLarge) {
					t.Fatalf("err = %v, want ErrTooLarge", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.input {
				t.Errorf("read %d bytes, want %d", len(got), tt.input)
			}
		})
	}
}

// TestCSVReadAllRejectsOversizeInput proves the bound is actually wired into
// the CSV path, not merely available to it.
func TestCSVReadAllRejectsOversizeInput(t *testing.T) {
	shrinkImportCap(t, 32)

	rows, err := csvReadAll(strings.NewReader("name,password\n"+strings.Repeat("a,b\n", 64)), "")
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if rows != nil {
		t.Errorf("rows = %v, want nil on refusal", rows)
	}

	rows, err = csvReadAll(strings.NewReader("name,password\nx,y\n"), "")
	if err != nil {
		t.Fatalf("a small file must still import: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("got %d rows, want 2", len(rows))
	}
}

// TestKeePassImportRejectsOversizeInput covers the KDBX decoder, which
// inflates a compressed payload and is therefore the most profitable decode
// path to point a bomb at.
func TestKeePassImportRejectsOversizeInput(t *testing.T) {
	shrinkImportCap(t, 32)

	kdbx := append([]byte{0x03, 0xd9, 0xa2, 0x96}, bytes.Repeat([]byte{0x41}, 4096)...)
	imp := &KeePassImporter{Password: "x"}
	_, err := ImportAll(imp, bytes.NewReader(kdbx))
	if err == nil {
		t.Fatal("an oversize database must be refused")
	}
	if !strings.Contains(err.Error(), ErrTooLarge.Error()) {
		t.Fatalf("err = %v, want it to name the size refusal", err)
	}
}
