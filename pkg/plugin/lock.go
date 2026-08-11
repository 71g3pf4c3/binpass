package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// LockName is the file recording what the user has approved.
const LockName = "plugins.lock"

// Grant records an approval the user gave for one plugin.
type Grant struct {
	// Name is the plugin the grant belongs to.
	Name string `json:"name"`
	// Version is the version that was approved.
	Version string `json:"version"`
	// Digest is the SHA-256 of the executable as approved, hex encoded.
	Digest string `json:"digest"`
	// Capabilities are the capabilities the user consented to.
	Capabilities Capabilities `json:"capabilities"`
	// GrantedAt is when consent was given.
	GrantedAt time.Time `json:"granted_at"`
}

// Lock is the set of grants, keyed by plugin name.
type Lock struct {
	// Version is the lock format version.
	Version int `json:"version"`
	// Grants are the recorded approvals.
	Grants map[string]Grant `json:"grants"`
}

// LoadLock reads the lock file, returning an empty lock when absent.
func LoadLock(path string) (*Lock, error) {
	data, err := os.ReadFile(path) //nolint:gosec // a path binpass owns.
	if os.IsNotExist(err) {
		return &Lock{Version: 1, Grants: map[string]Grant{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var l Lock
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("plugin: %s is corrupt: %w", path, err)
	}
	if l.Grants == nil {
		l.Grants = map[string]Grant{}
	}
	return &l, nil
}

// Save writes the lock file atomically, so that an interrupted write cannot
// leave behind a lock that grants something nobody approved.
func (l *Lock) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".plugins.lock-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Grant records consent for a plugin at its current digest.
func (l *Lock) Grant(m *Manifest, digest string) {
	if l.Grants == nil {
		l.Grants = map[string]Grant{}
	}
	l.Grants[m.Name] = Grant{
		Name:         m.Name,
		Version:      m.Version,
		Digest:       digest,
		Capabilities: m.Capabilities,
		GrantedAt:    time.Now().UTC(),
	}
}

// Revoke removes a plugin's grant.
func (l *Lock) Revoke(name string) { delete(l.Grants, name) }

// Names returns the granted plugin names in a stable order.
func (l *Lock) Names() []string {
	out := make([]string, 0, len(l.Grants))
	for n := range l.Grants {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// GrantState is the result of checking a plugin against the lock.
type GrantState int

// The states a plugin can be in relative to recorded consent.
const (
	// GrantMissing means the plugin has never been approved.
	GrantMissing GrantState = iota
	// GrantStale means the executable changed since it was approved.
	GrantStale
	// GrantWidened means the manifest now asks for more than was approved.
	GrantWidened
	// GrantValid means the recorded consent still covers this plugin.
	GrantValid
)

// String names the state.
func (g GrantState) String() string {
	switch g {
	case GrantMissing:
		return "not approved"
	case GrantStale:
		return "changed since approval"
	case GrantWidened:
		return "requests more than approved"
	case GrantValid:
		return "approved"
	default:
		return "unknown"
	}
}

// Check reports whether recorded consent still covers a plugin.
//
// Consent is tied to a specific executable and a specific set of
// capabilities. An update that rewrites the binary, or a manifest edited to
// ask for more, invalidates it: otherwise approving a plugin once would
// approve every future version of it, including one the author never wrote.
func (l *Lock) Check(m *Manifest, digest string) GrantState {
	g, ok := l.Grants[m.Name]
	if !ok {
		return GrantMissing
	}
	if g.Digest != digest {
		return GrantStale
	}
	if widens(g.Capabilities, m.Capabilities) {
		return GrantWidened
	}
	return GrantValid
}

// widens reports whether want asks for anything have does not already allow.
func widens(have, want Capabilities) bool {
	if want.Decrypt && !have.Decrypt {
		return true
	}
	return !covers(have.ReadPaths, want.ReadPaths) ||
		!covers(have.WritePaths, want.WritePaths) ||
		!coversHosts(have.Network, want.Network) ||
		!coversExec(have.Exec, want.Exec)
}

// covers reports whether every wanted pattern is already granted.
//
// Patterns are compared by meaning, not by string: a grant of "a/**" covers a
// later request for "a/b", and re-prompting for that would train the user to
// approve without reading.
func covers(have, want []string) bool {
	for _, w := range want {
		if !patternCovered(have, w) {
			return false
		}
	}
	return true
}

// patternCovered reports whether some granted pattern subsumes want.
func patternCovered(have []string, want string) bool {
	for _, h := range have {
		if h == want || subsumes(h, want) {
			return true
		}
	}
	return false
}

// subsumes reports whether pattern a covers everything pattern b can match.
//
// Deciding this in general is undecidable-adjacent and easy to get subtly
// wrong, so only the cases with an obvious answer are accepted and everything
// else is reported as not covered. Being wrong in this direction costs an
// extra prompt; being wrong in the other direction grants access silently.
func subsumes(a, b string) bool {
	if a == "**" {
		return true
	}
	// "x/**" covers "x", "x/anything" and "x/any/depth".
	if rest, ok := trimSuffix(a, "/**"); ok {
		return b == rest || hasPathPrefix(b, rest)
	}
	return false
}

// trimSuffix removes suffix from s, reporting whether it was present.
func trimSuffix(s, suffix string) (string, bool) {
	if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)], true
	}
	return "", false
}

// hasPathPrefix reports whether p lies beneath prefix.
func hasPathPrefix(p, prefix string) bool {
	return len(p) > len(prefix) && p[:len(prefix)] == prefix && p[len(prefix)] == '/'
}

// coversHosts reports whether every wanted host is already granted.
func coversHosts(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] && !set["*"] {
			return false
		}
	}
	return true
}

// coversExec reports whether every wanted binary is already granted.
func coversExec(have, want []string) bool { return coversHosts(have, want) }

// DigestFile returns the hex SHA-256 of a file, which is what a grant is
// bound to.
func DigestFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the plugin binary being approved.
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
