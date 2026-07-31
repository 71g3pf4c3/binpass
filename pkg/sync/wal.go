package sync

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// OpType is the kind of a journalled local operation.
type OpType string

// Operation types.
const (
	// OpSet records a create-or-update of an entry.
	OpSet OpType = "set"
	// OpRemove records a deletion of an entry.
	OpRemove OpType = "remove"
)

// Op is a single write-ahead-log record describing a local change that has
// been applied to the working tree but not yet committed to a remote.
type Op struct {
	// Type is the operation kind.
	Type OpType `json:"type"`
	// Path is the logical entry path.
	Path string `json:"path"`
	// Object is the new object ID for OpSet.
	Object string `json:"oid,omitempty"`
	// Size is the entry size for OpSet.
	Size int64 `json:"size,omitempty"`
	// Kind is the entry kind for OpSet.
	Kind string `json:"kind,omitempty"`
	// At is when the operation occurred.
	At time.Time `json:"at"`
}

// WAL is an append-only journal of uncommitted operations. Records are newline
// -delimited JSON so a crash mid-append leaves at most one corrupt trailing
// line, which Load skips.
type WAL struct {
	// path is the journal file path.
	path string
}

// NewWAL returns a WAL backed by path.
func NewWAL(path string) *WAL { return &WAL{path: path} }

// Append durably appends op to the journal.
func (w *WAL) Append(op Op) error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return fmt.Errorf("wal: mkdir: %w", err)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("wal: open: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(op)
	if err != nil {
		return fmt.Errorf("wal: marshal: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("wal: write: %w", err)
	}
	return f.Sync()
}

// Load returns all valid journalled operations, skipping a corrupt trailing
// record left by a crash mid-append.
func (w *WAL) Load() ([]Op, error) {
	f, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("wal: open: %w", err)
	}
	defer f.Close()

	var ops []Op
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var op Op
		if err := json.Unmarshal(sc.Bytes(), &op); err != nil {
			// Corrupt (likely partial) trailing line: stop, ignore the rest.
			break
		}
		ops = append(ops, op)
	}
	return ops, sc.Err()
}

// Clear truncates the journal after a successful commit.
func (w *WAL) Clear() error {
	if err := os.Remove(w.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("wal: clear: %w", err)
	}
	return nil
}
