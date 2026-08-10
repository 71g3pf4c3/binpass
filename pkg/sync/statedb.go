package sync

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// StateDB persists sync state outside the password store (§1). It stores the
// base snapshot (the file states at the moment of the last successful sync)
// and a write-ahead log that is replayed on startup if the process was
// interrupted mid-operation.
//
// # Location
//
// The database lives at $XDG_STATE_HOME/binpass/state.db, never inside the
// password store. If the state leaked into the store it would end up in git
// history and on cloud drives, and `pass git status` would show noise.
//
// # Concurrency
//
// All bbolt operations are serialised through the Bolt transaction model.
// The StateDB itself is safe for concurrent use from multiple goroutines, but
// it is NOT safe for multiple processes: the bbolt file lock will prevent
// concurrent opens, and the intended usage is one StateDB per binpass process.
type StateDB struct {
	db  *bolt.DB
	dir string
	wal *wal
}

// stateBucket stores the base file states.
var stateBucket = []byte("state")

// walBucket stores pending WAL entries.
var walBucket = []byte("wal")

// metaBucket stores metadata (device ID, last sync time, etc.).
var metaBucket = []byte("meta")

// OpenStateDB opens or creates the state database at dir. The directory is
// created if it does not exist. On open, any uncommitted WAL entries are
// replayed to restore consistency.
func OpenStateDB(dir string) (*StateDB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sync: create state dir: %w", err)
	}
	path := filepath.Join(dir, "state.db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("sync: open state.db: %w", err)
	}
	s := &StateDB{db: db, dir: dir, wal: newWAL()}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.replayWAL(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sync: WAL replay: %w", err)
	}
	return s, nil
}

// init creates the required buckets.
func (s *StateDB) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{stateBucket, walBucket, metaBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("sync: create bucket %q: %w", name, err)
			}
		}
		return nil
	})
}

// Close releases the database lock. It must be called when the StateDB is no
// longer needed.
func (s *StateDB) Close() error {
	return s.db.Close()
}

// DeviceID returns the persisted device ID, or the empty string if none has
// been set.
func (s *StateDB) DeviceID() (DeviceID, error) {
	var id DeviceID
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(metaBucket)
		v := b.Get([]byte("device_id"))
		if v != nil {
			id = DeviceID(v)
		}
		return nil
	})
	return id, err
}

// SetDeviceID persists the device ID. It is called once during `binpass init`
// or on first sync.
func (s *StateDB) SetDeviceID(id DeviceID) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(metaBucket)
		return b.Put([]byte("device_id"), []byte(id))
	})
}

// LoadBase returns the base snapshot: the file states at the moment of the
// last successful sync. An empty or missing bucket returns an empty snapshot.
func (s *StateDB) LoadBase() (Snapshot, error) {
	snap := make(Snapshot)
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(stateBucket)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var fs FileState
			if err := json.Unmarshal(v, &fs); err != nil {
				return fmt.Errorf("sync: unmarshal %q: %w", string(k), err)
			}
			snap[string(k)] = &fs
		}
		return nil
	})
	return snap, err
}

// SaveBase atomically replaces the base snapshot with snap. The entire
// operation runs in a single Bolt transaction, so a crash leaves either the
// old or the new state, never a partial mix.
func (s *StateDB) SaveBase(snap Snapshot) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(stateBucket)
		// Delete entries not in the new snapshot.
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if _, ok := snap[string(k)]; !ok {
				_ = b.Delete(k)
			}
		}
		// Write new entries.
		for path, fs := range snap {
			data, err := json.Marshal(fs)
			if err != nil {
				return fmt.Errorf("sync: marshal %q: %w", path, err)
			}
			if err := b.Put([]byte(path), data); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateFile updates a single file state in the base snapshot. It is the
// granularity of a single sync action: each file is committed independently
// so that a failure halfway through leaves the rest intact.
func (s *StateDB) UpdateFile(fs *FileState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(stateBucket)
		data, err := json.Marshal(fs)
		if err != nil {
			return fmt.Errorf("sync: marshal %q: %w", fs.Path, err)
		}
		return b.Put([]byte(fs.Path), data)
	})
}

// DeleteFile removes a file from the base snapshot. This is called when a file
// has been deleted on both sides and confirmed by the merge engine.
func (s *StateDB) DeleteFile(path string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(stateBucket).Delete([]byte(path))
	})
}

// LastSync returns the timestamp of the last successful sync, or the zero time.
func (s *StateDB) LastSync() (time.Time, error) {
	var t time.Time
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(metaBucket).Get([]byte("last_sync"))
		if v != nil {
			return t.UnmarshalText(v)
		}
		return nil
	})
	return t, err
}

// RecordSync records the current time as the last successful sync.
func (s *StateDB) RecordSync() error {
	now := time.Now().UTC()
	text, err := now.MarshalText()
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(metaBucket).Put([]byte("last_sync"), text)
	})
}

// ---- WAL (write-ahead log) ----

// walEntry represents a pending state mutation that has not been fully applied.
// If the process is killed mid-operation, replaying these entries restores
// consistency (§8.6).
type walEntry struct {
	// Op is the operation type: "set" or "delete".
	Op string `json:"op"`
	// Path is the store-relative path of the affected file.
	Path string `json:"path"`
	// State is the new file state (for "set" operations).
	State *FileState `json:"state,omitempty"`
}

// wal manages write-ahead log entries. Entries are written to the WAL bucket
// before the actual state mutation and removed after successful commit.
type wal struct {
	mu      sync.Mutex
	pending []walEntry
}

func newWAL() *wal { return &wal{} }

// Begin appends an entry to the in-memory WAL and persists it to the WAL
// bucket. It must be called before the actual state mutation.
func (w *wal) Begin(s *StateDB, entry walEntry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, entry)
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		seq, _ := tx.Bucket(walBucket).NextSequence()
		key := []byte(fmt.Sprintf("%020d", seq))
		return tx.Bucket(walBucket).Put(key, data)
	})
}

// Commit removes the oldest WAL entry. It must be called after the state
// mutation has been successfully applied.
func (w *wal) Commit(s *StateDB) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) == 0 {
		return nil
	}
	w.pending = w.pending[1:]
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(walBucket)
		c := b.Cursor()
		if k, _ := c.First(); k != nil {
			return b.Delete(k)
		}
		return nil
	})
}

// replayWAL replays any uncommitted WAL entries from a previous crash.
// Each pending "set" entry is applied to the state bucket; "delete" entries
// remove from the state bucket. After replay, the WAL is cleared.
func (s *StateDB) replayWAL() error {
	var entries []walEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(walBucket)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var e walEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return fmt.Errorf("sync: unmarshal WAL entry %q: %w", string(k), err)
			}
			entries = append(entries, e)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}

	// Apply each entry.
	return s.db.Update(func(tx *bolt.Tx) error {
		state := tx.Bucket(stateBucket)
		walB := tx.Bucket(walBucket)
		for _, e := range entries {
			switch e.Op {
			case "set":
				data, err := json.Marshal(e.State)
				if err != nil {
					return err
				}
				if err := state.Put([]byte(e.Path), data); err != nil {
					return err
				}
			case "delete":
				_ = state.Delete([]byte(e.Path))
			}
		}
		// Clear the WAL.
		c := walB.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			_ = walB.Delete(k)
		}
		return nil
	})
}

// ---- Consistency check (fsck) ----

// ErrStateInStore reports that the state database was found inside the
// password store, which would leak device-specific data through git and cloud.
var ErrStateInStore = errors.New("sync: state.db is inside the password store; move it to XDG_STATE_HOME/binpass")

// CheckStateLocation verifies that the state database is not inside the
// password store directory. This is a prerequisite for `binpass fsck`.
func CheckStateLocation(stateDir, storeDir string) error {
	rel, err := filepath.Rel(storeDir, stateDir)
	if err != nil {
		return nil // different volumes, cannot be inside.
	}
	if rel == "." || !filepath.IsAbs(rel) && !strings.HasPrefix(rel, "..") {
		return ErrStateInStore
	}
	return nil
}
