// Package identity resolves age decryption keys from the sources binpass
// supports: explicit files, the passage identities file, the standard age key
// file, and age plugin identities backed by hardware tokens.
//
// Resolution is lazy and ordered (see Resolver.Load): nothing is read, and no
// token is touched, until a decryption actually needs a key.
package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// ErrNone reports that no identity source yielded a usable key.
var ErrNone = errors.New("identity: no identity found")

// Kind classifies where an identity comes from.
type Kind string

// Identity kinds.
const (
	// KindFile is a plaintext age key file.
	KindFile Kind = "file"
	// KindPlugin is an age plugin identity, typically a hardware token.
	KindPlugin Kind = "plugin"
)

// Source is one place identities can be loaded from.
type Source struct {
	// Kind classifies the source.
	Kind Kind
	// Path is the file the identities came from, for diagnostics.
	Path string
	// Identities are the keys the source yielded.
	Identities []age.Identity
	// Describe is a human-readable summary, e.g. a plugin name.
	Describe string
}

// Resolver locates identities in priority order.
type Resolver struct {
	// Explicit is the --identity flag or BINPASS_IDENTITY; when set, it is
	// the only source consulted, so an explicit choice is never silently
	// widened.
	Explicit string
	// Files are the fallback identity files, tried in order.
	Files []string
	// PluginUI drives interactive prompts from age plugins.
	PluginUI PluginUI
}

// DefaultFiles returns the fallback identity files in priority order:
// binpass's own locations, the standard age key file, then passage's.
//
// Both ~/.local/share/binpass and ~/.config/binpass are searched. The
// architecture places the identity in the data directory, but init has
// historically written it next to the config, and a key the tool created
// itself must never be a key the tool cannot find.
func DefaultFiles() []string {
	var out []string
	if dir := dataDir(); dir != "" {
		out = append(out, filepath.Join(dir, "identities.age"))
	}
	if dir := configDir(); dir != "" {
		out = append(out,
			filepath.Join(dir, "binpass", "identities.age"),
			filepath.Join(dir, "age", "keys.txt"),
		)
	}
	if p := os.Getenv("PASSAGE_IDENTITIES_FILE"); p != "" {
		out = append(out, p)
	}
	return out
}

// NewResolver builds a resolver from the environment and an optional explicit
// path taken from --identity.
func NewResolver(explicit string) *Resolver {
	if explicit == "" {
		explicit = os.Getenv("BINPASS_IDENTITY")
	}
	return &Resolver{Explicit: explicit, Files: DefaultFiles()}
}

// Load returns every identity found, in priority order. Sources that do not
// exist are skipped; a source that exists but cannot be parsed is an error,
// because silently ignoring a broken key file hides the real problem.
func (r *Resolver) Load() ([]age.Identity, error) {
	sources, err := r.Sources()
	if err != nil {
		return nil, err
	}
	var out []age.Identity
	for _, s := range sources {
		out = append(out, s.Identities...)
	}
	if len(out) == 0 {
		return nil, r.notFound()
	}
	return out, nil
}

// notFound builds an error naming every location that was searched. "No
// identity found" on its own sends the user hunting for a key that usually
// exists a directory away from where the tool looked.
func (r *Resolver) notFound() error {
	if r.Explicit != "" {
		return fmt.Errorf("%w: %s holds no age identity", ErrNone, r.Explicit)
	}
	var sb strings.Builder
	sb.WriteString("searched:")
	for _, p := range r.Files {
		if p == "" {
			continue
		}
		sb.WriteString("\n  ")
		sb.WriteString(p)
		if _, err := os.Stat(p); err == nil {
			sb.WriteString("  (exists, but holds no identity)")
		}
	}
	sb.WriteString("\n\nGenerate one with:  age-keygen -o ")
	if dir := dataDir(); dir != "" {
		sb.WriteString(filepath.Join(dir, "identities.age"))
	} else {
		sb.WriteString("~/.local/share/binpass/identities.age")
	}
	sb.WriteString("\nOr point binpass at an existing key with --identity or BINPASS_IDENTITY.")
	return fmt.Errorf("%w\n%s", ErrNone, sb.String())
}

// Sources returns the identity sources that yielded keys, in priority order.
func (r *Resolver) Sources() ([]Source, error) {
	if r.Explicit != "" {
		s, err := r.loadFile(r.Explicit)
		if err != nil {
			return nil, err
		}
		return []Source{s}, nil
	}
	var out []Source
	for _, path := range r.Files {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		s, err := r.loadFile(path)
		if err != nil {
			return nil, err
		}
		if len(s.Identities) > 0 {
			out = append(out, s)
		}
	}
	return out, nil
}

// loadFile parses one identity file, resolving plugin identity lines through
// their age-plugin-* binaries.
func (r *Resolver) loadFile(path string) (Source, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is user-supplied by design.
	if err != nil {
		return Source{}, fmt.Errorf("identity: %w", err)
	}
	ids, kind, err := ParseIdentities(string(data), r.PluginUI)
	if err != nil {
		return Source{}, fmt.Errorf("identity: %s: %w", path, err)
	}
	return Source{Kind: kind, Path: path, Identities: ids, Describe: path}, nil
}

// ParseIdentities parses the contents of an age identity file. Both native
// AGE-SECRET-KEY-1 lines and AGE-PLUGIN-* lines are accepted; blank lines and
// '#' comments are ignored.
func ParseIdentities(data string, ui PluginUI) ([]age.Identity, Kind, error) {
	kind := KindFile
	var out []age.Identity
	for n, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(strings.ToUpper(line), "AGE-PLUGIN-"):
			id, err := newPluginIdentity(line, ui)
			if err != nil {
				return nil, kind, fmt.Errorf("line %d: %w", n+1, err)
			}
			kind = KindPlugin
			out = append(out, id)
		default:
			id, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, kind, fmt.Errorf("line %d: %w", n+1, err)
			}
			out = append(out, id)
		}
	}
	return out, kind, nil
}
