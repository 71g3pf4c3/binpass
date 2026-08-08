package plugin

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// ErrNotFound reports that no plugin provides a command.
var ErrNotFound = errors.New("plugin: not found")

// Plugin is a discovered plugin: where it lives and what it declares.
type Plugin struct {
	// Manifest is the parsed manifest, or a synthesised one for a bare
	// executable found on PATH.
	Manifest *Manifest
	// Path is the absolute path to the executable.
	Path string
	// Dir is the directory the plugin was found in.
	Dir string
	// Managed reports whether binpass installed this plugin, which is what
	// decides whether it can be removed or updated.
	Managed bool
}

// Source describes where plugins may be found.
type Source struct {
	// Dirs are the managed plugin directories, searched in order.
	Dirs []string
	// PathLookup enables discovery of binpass-* executables on PATH, which
	// is how the git-style convention works.
	PathLookup bool
}

// DefaultSource returns the search locations, in precedence order.
//
// Managed directories come first: a plugin the user explicitly installed and
// approved should not be shadowed by an executable that happens to sit
// earlier on PATH.
func DefaultSource(dataDir, storeDir string) Source {
	var dirs []string
	if dataDir != "" {
		dirs = append(dirs, filepath.Join(dataDir, "plugins"))
	}
	// Plugins inside the store travel with it when the store syncs. That is
	// convenient and it is also a trust decision, so they rank below the
	// local ones and are called out at install time.
	if storeDir != "" {
		dirs = append(dirs, filepath.Join(storeDir, ".binpass", "plugins"))
	}
	return Source{Dirs: dirs, PathLookup: true}
}

// Discover returns every plugin that can be found, sorted by name, with
// earlier sources winning when a name repeats.
func (s Source) Discover() []*Plugin {
	seen := map[string]bool{}
	var out []*Plugin

	for _, dir := range s.Dirs {
		for _, p := range discoverDir(dir) {
			if seen[p.Manifest.Name] {
				continue
			}
			seen[p.Manifest.Name] = true
			out = append(out, p)
		}
	}
	if s.PathLookup {
		for _, p := range discoverPath() {
			if seen[p.Manifest.Name] {
				continue
			}
			seen[p.Manifest.Name] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Manifest.Name < out[j].Manifest.Name
	})
	return out
}

// Find returns the plugin providing a command.
func (s Source) Find(name string) (*Plugin, error) {
	for _, p := range s.Discover() {
		if p.Manifest.Name == name {
			return p, nil
		}
	}
	return nil, ErrNotFound
}

// discoverDir reads one managed plugin directory. Each plugin is a
// subdirectory holding a manifest and its executable, which keeps a plugin's
// files together and lets the manifest sit next to what it describes.
func discoverDir(dir string) []*Plugin {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []*Plugin
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		p, err := load(sub)
		if err != nil {
			// A malformed plugin is skipped rather than fatal: one bad
			// directory must not stop every other plugin from working.
			continue
		}
		out = append(out, p)
	}
	return out
}

// load reads a plugin from its directory.
func load(dir string) (*Plugin, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestName)) //nolint:gosec // a plugin directory binpass owns.
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, err
	}
	// Recipes are data, not executables, so they have nothing to run.
	if m.Level == LevelRecipe {
		return &Plugin{Manifest: m, Dir: dir, Managed: true}, nil
	}
	bin := filepath.Join(dir, m.Binary())
	if _, err := os.Stat(bin); err != nil {
		return nil, err
	}
	return &Plugin{Manifest: m, Path: bin, Dir: dir, Managed: true}, nil
}

// discoverPath finds binpass-* executables on PATH, the git-style convention.
//
// These carry no manifest, so nothing about them was ever approved. They are
// synthesised with empty capabilities, which means they get no access back
// through binpass; they run, and they can use the store only as much as any
// other program the user could have started themselves.
func discoverPath() []*Plugin {
	var out []*Plugin
	seen := map[string]bool{}

	for _, c := range scanPath() {
		if seen[c.Name] || !c.Executable {
			continue
		}
		seen[c.Name] = true
		out = append(out, &Plugin{
			Manifest: &Manifest{
				Name:        c.Name,
				API:         APIVersion,
				Level:       LevelExec,
				Description: "unmanaged executable on PATH",
			},
			Path: c.Path,
		})
	}
	return out
}

// executable reports whether a path is a file that can be run.
func executable(path string) bool {
	// The path is built from a PATH directory and a file name read out of
	// it, so there is no traversal to prevent: the caller is asking about a
	// file that was just enumerated, and only its mode is inspected.
	fi, err := os.Stat(path) //nolint:gosec // an enumerated directory entry, not user input.
	if err != nil || fi.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return fi.Mode().Perm()&0o111 != 0
}
