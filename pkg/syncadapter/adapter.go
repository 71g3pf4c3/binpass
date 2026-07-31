// Package syncadapter bridges the password store to the sync engine. It
// implements sync.Local and sync.State on top of a store.Store plus a
// .binpass/ state directory that holds the signing key, the base manifest,
// and a content-addressed cache of ciphertext objects.
package syncadapter

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/manifest"
	"github.com/71g3pf4c3/binpass/pkg/store"
)

// stateDir is the per-store metadata directory name.
const stateDir = ".binpass"

// Adapter implements sync.Local and sync.State for a store.
type Adapter struct {
	// st is the underlying password store.
	st *store.Store
	// deviceID identifies this device.
	deviceID string
	// storeID is the store's stable UUID.
	storeID string
}

// New builds an Adapter, loading or creating the store ID and device ID.
func New(st *store.Store, deviceID string) (*Adapter, error) {
	a := &Adapter{st: st, deviceID: deviceID}
	if err := os.MkdirAll(a.objectsDir(), 0o700); err != nil {
		return nil, fmt.Errorf("syncadapter: mkdir objects: %w", err)
	}
	id, err := a.loadOrCreateStoreID()
	if err != nil {
		return nil, err
	}
	a.storeID = id
	return a, nil
}

// binpassDir returns the .binpass state directory path.
func (a *Adapter) binpassDir() string { return filepath.Join(a.st.Dir(), stateDir) }

// objectsDir returns the object cache directory.
func (a *Adapter) objectsDir() string { return filepath.Join(a.binpassDir(), "objects") }

// StoreID returns the store UUID.
func (a *Adapter) StoreID() string { return a.storeID }

// DeviceID returns the device identifier.
func (a *Adapter) DeviceID() string { return a.deviceID }

// loadOrCreateStoreID reads the persisted store UUID or creates one.
func (a *Adapter) loadOrCreateStoreID() (string, error) {
	path := filepath.Join(a.binpassDir(), "store_id")
	if data, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	id := newUUID()
	if err := os.MkdirAll(a.binpassDir(), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("syncadapter: write store id: %w", err)
	}
	return id, nil
}

// SigningKey loads or creates the Ed25519 manifest-signing key. The key is
// stored under .binpass/signing.key (0600). In production this file would be
// itself age-encrypted; here it is protected by filesystem permissions.
func (a *Adapter) SigningKey() (ed25519.PrivateKey, error) {
	path := filepath.Join(a.binpassDir(), "signing.key")
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("syncadapter: malformed signing key")
		}
		return ed25519.PrivateKey(data), nil
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("syncadapter: gen signing key: %w", err)
	}
	if err := os.MkdirAll(a.binpassDir(), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, fmt.Errorf("syncadapter: write signing key: %w", err)
	}
	return priv, nil
}

// objectCachePath maps an object ID to its cache path.
func (a *Adapter) objectCachePath(id string) string {
	return filepath.Join(a.objectsDir(), strings.TrimPrefix(id, "b3:"))
}

// cacheObject stores ciphertext in the object cache under its ID.
func (a *Adapter) cacheObject(ciphertext []byte) (string, error) {
	id := manifest.ObjectID(ciphertext)
	if err := os.WriteFile(a.objectCachePath(id), ciphertext, 0o600); err != nil {
		return "", fmt.Errorf("syncadapter: cache object: %w", err)
	}
	return id, nil
}

// BuildManifest constructs the current manifest by hashing every secret's
// ciphertext, carrying version vectors forward from base and bumping this
// device's counter for changed or new entries.
func (a *Adapter) BuildManifest(base *manifest.Manifest) (*manifest.Manifest, error) {
	m := manifest.New(a.storeID)
	if base != nil {
		m.Generation = base.Generation
	}

	names, err := a.st.List()
	if err != nil {
		return nil, err
	}
	live := make(map[string]struct{}, len(names))

	for _, name := range names {
		ct, err := a.st.ReadCiphertext(name)
		if err != nil {
			return nil, err
		}
		id, err := a.cacheObject(ct)
		if err != nil {
			return nil, err
		}
		live[name] = struct{}{}

		entry := manifest.Entry{
			Object: id,
			Size:   int64(len(ct)),
			Kind:   manifest.KindSecret,
		}
		if base != nil {
			if prev, ok := base.Entries[name]; ok {
				entry.Version = manifest.MergeVV(nil, prev.Version)
				if prev.Object != id {
					entry.Version = manifest.Bump(prev.Version, a.deviceID)
				}
			}
		}
		if entry.Version == nil {
			entry.Version = manifest.Bump(nil, a.deviceID)
		}
		m.Entries[name] = entry
	}

	// Carry forward tombstones for entries deleted locally since base.
	if base != nil {
		for name, prev := range base.Entries {
			if _, stillLive := live[name]; stillLive || prev.Deleted {
				if prev.Deleted {
					m.Entries[name] = prev
				}
				continue
			}
			now := time.Now()
			m.Entries[name] = manifest.Entry{
				Kind:      prev.Kind,
				Version:   manifest.Bump(prev.Version, a.deviceID),
				Deleted:   true,
				DeletedAt: &now,
			}
		}
	}
	return m, nil
}

// ReadObject returns ciphertext for an object ID from the cache or, failing
// that, by scanning the live tree.
func (a *Adapter) ReadObject(id string) ([]byte, error) {
	if data, err := os.ReadFile(a.objectCachePath(id)); err == nil {
		return data, nil
	}
	names, err := a.st.List()
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		ct, err := a.st.ReadCiphertext(name)
		if err != nil {
			continue
		}
		if manifest.ObjectID(ct) == id {
			return ct, nil
		}
	}
	return nil, fmt.Errorf("syncadapter: object %s not found", id)
}

// WriteObject stores pulled ciphertext both in the cache and at its logical
// path in the working tree.
func (a *Adapter) WriteObject(path, id string, ciphertext []byte) error {
	if err := os.WriteFile(a.objectCachePath(id), ciphertext, 0o600); err != nil {
		return fmt.Errorf("syncadapter: cache pulled object: %w", err)
	}
	return a.st.WriteCiphertext(path, ciphertext)
}

// ApplyDeletion removes path from the working tree, tolerating absence.
func (a *Adapter) ApplyDeletion(path string) error {
	if !a.st.Exists(path) {
		return nil
	}
	return a.st.RemoveByName(path)
}

// WriteConflictCopy stores the losing local side as a timestamped sibling.
func (a *Adapter) WriteConflictCopy(path string, ciphertext []byte) (string, error) {
	sibling := fmt.Sprintf("%s.conflict-%s-%s", path, a.deviceID, time.Now().UTC().Format("20060102T150405"))
	if err := a.st.WriteCiphertext(sibling, ciphertext); err != nil {
		return "", err
	}
	return sibling, nil
}

// HasEntry reports whether a working-tree file exists at path.
func (a *Adapter) HasEntry(path string) bool { return a.st.Exists(path) }

// EntryObject returns the object ID of the working-tree file at path, or ""
// if it does not exist.
func (a *Adapter) EntryObject(path string) string {
	if !a.st.Exists(path) {
		return ""
	}
	ct, err := a.st.ReadCiphertext(path)
	if err != nil {
		return ""
	}
	return manifest.ObjectID(ct)
}

// LoadBase returns the persisted base manifest, or nil if none.
func (a *Adapter) LoadBase() (*manifest.Manifest, error) {
	path := filepath.Join(a.binpassDir(), "state", "base.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("syncadapter: read base: %w", err)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("syncadapter: decode base: %w", err)
	}
	return &m, nil
}

// SaveBase persists the merged manifest as the new base.
func (a *Adapter) SaveBase(m *manifest.Manifest) error {
	dir := filepath.Join(a.binpassDir(), "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("syncadapter: encode base: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "base.json"), data, 0o600)
}
