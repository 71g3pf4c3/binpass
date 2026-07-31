package sync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWALAppendLoad(t *testing.T) {
	w := NewWAL(filepath.Join(t.TempDir(), "journal.wal"))
	require.NoError(t, w.Append(Op{Type: OpSet, Path: "a", Object: "b3:1"}))
	require.NoError(t, w.Append(Op{Type: OpRemove, Path: "b"}))

	ops, err := w.Load()
	require.NoError(t, err)
	require.Len(t, ops, 2)
	assert.Equal(t, OpSet, ops[0].Type)
	assert.Equal(t, "b", ops[1].Path)
}

func TestWALLoadMissing(t *testing.T) {
	w := NewWAL(filepath.Join(t.TempDir(), "none.wal"))
	ops, err := w.Load()
	require.NoError(t, err)
	assert.Nil(t, ops)
}

func TestWALSkipsCorruptTrailing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.wal")
	w := NewWAL(path)
	require.NoError(t, w.Append(Op{Type: OpSet, Path: "a"}))
	// Simulate a crash mid-append: a partial trailing line.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"type":"set","path":"b`)
	f.Close()

	ops, err := w.Load()
	require.NoError(t, err)
	require.Len(t, ops, 1) // only the first complete record
	assert.Equal(t, "a", ops[0].Path)
}

func TestWALClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.wal")
	w := NewWAL(path)
	require.NoError(t, w.Append(Op{Type: OpSet, Path: "a"}))
	require.NoError(t, w.Clear())
	ops, err := w.Load()
	require.NoError(t, err)
	assert.Nil(t, ops)
}
