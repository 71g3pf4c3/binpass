package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// StoreSnapshot maps the name of every plugin found inside a store to a
// digest of what running it would do.
type StoreSnapshot map[string]string

// StorePluginsDir returns the plugin directory that travels inside a store.
func StorePluginsDir(storeDir string) string {
	if storeDir == "" {
		return ""
	}
	return filepath.Join(storeDir, ".binpass", "plugins")
}

// SnapshotStorePlugins digests the plugins currently inside the store.
//
// Only the store's own directory is read: a plugin in the user's data
// directory was installed deliberately, while this one arrived with whatever
// the remote served.
func SnapshotStorePlugins(storeDir string) StoreSnapshot {
	out := StoreSnapshot{}
	dir := StorePluginsDir(storeDir)
	if dir == "" {
		return out
	}
	for _, p := range (Source{Dirs: []string{dir}}).Discover() {
		out[p.Manifest.Name] = storePluginDigest(p)
	}
	return out
}

// storePluginDigest digests both halves of what a plugin would do: the
// manifest, because it chooses the capabilities and which file is executed,
// and that file, because recognising a name must not amount to recognising
// every future body served under it.
func storePluginDigest(p *Plugin) string {
	h := sha256.New()
	if data, err := os.ReadFile(filepath.Join(p.Dir, ManifestName)); err == nil { //nolint:gosec // a directory just enumerated by Discover.
		_, _ = h.Write(data)
	}
	if p.Path != "" {
		d, err := DigestFile(p.Path)
		if err != nil {
			// An unreadable binary must not digest the same as a readable
			// one, or swapping it in would look like no change at all.
			d = "unreadable:" + err.Error()
		}
		_, _ = io.WriteString(h, d)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// StorePluginDiff reports how the plugins inside a store changed.
type StorePluginDiff struct {
	// Added are plugins that were not there before.
	Added []string
	// Changed are plugins whose manifest or executable is not the one that
	// was there before.
	Changed []string
	// Removed are plugins that are gone.
	Removed []string
}

// Empty reports whether nothing changed.
func (d StorePluginDiff) Empty() bool {
	return len(d.Added) == 0 && len(d.Changed) == 0 && len(d.Removed) == 0
}

// DiffStorePlugins compares two snapshots of a store's plugin directory.
//
// A plugin inside the store dispatches on the first non-builtin word of any
// invocation — including a typo — so one appearing or changing after a sync
// is the moment to say so. Precedence and approval are decided elsewhere;
// this answers only "is this the same thing as last time?", which is what
// nothing in the tree asked before.
func DiffStorePlugins(before, after StoreSnapshot) StorePluginDiff {
	var d StorePluginDiff
	for name, digest := range after {
		prev, known := before[name]
		switch {
		case !known:
			d.Added = append(d.Added, name)
		case prev != digest:
			d.Changed = append(d.Changed, name)
		}
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			d.Removed = append(d.Removed, name)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Changed)
	sort.Strings(d.Removed)
	return d
}
