// Package plugin implements binpass's extension system.
//
// pass extends itself by sourcing bash functions, which gives extensions the
// run of the program's internals and makes every internal detail a public
// interface. binpass does not do that. Plugins are separate processes that
// talk to a stable command line, and what they may reach is declared up front
// in a manifest the user approves.
//
// # The boundary, stated honestly
//
// A level 1 plugin is an ordinary process running as the user. It can read
// the store directly, ignore binpass entirely, and do anything its owner
// could do. The capability model constrains what a plugin can obtain *through
// binpass*: it is a guard rail against a careless plugin and an audit trail
// of what each one asked for. It is not a sandbox, and nothing here will stop
// hostile code. Anyone claiming otherwise is selling something.
//
// Level 3 plugins run under wazero, where isolation is real because the guest
// has no file or network access at all.
package plugin

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// APIVersion is the plugin contract version exported as BINPASS_API.
//
// It changes only when the contract breaks: the environment variables, the
// machine-readable output schemas, or the manifest format. Plugins are
// expected to refuse to run against an API version they do not know.
const APIVersion = 1

// ManifestName is the file every installed plugin carries beside its binary.
const ManifestName = "plugin.yaml"

// The plugin mechanisms, in ascending order of what they demand of an author.
const (
	// LevelExec is an executable providing a subcommand, in any language.
	LevelExec = 1
	// LevelRecipe is a declarative YAML recipe, with no code at all.
	LevelRecipe = 2
	// LevelWASM is a WebAssembly module, which runs genuinely sandboxed.
	LevelWASM = 3
)

// Manifest describes a plugin and the access it requests.
type Manifest struct {
	// Name is the plugin name, which decides the subcommand it provides.
	Name string `yaml:"name"`
	// Version is the plugin's own version string.
	Version string `yaml:"version"`
	// Description is a one-line summary shown at install time.
	Description string `yaml:"description,omitempty"`
	// API is the contract version the plugin was written against.
	API int `yaml:"api"`
	// Level is the plugin mechanism: 1 subcommand, 2 recipe, 3 wasm.
	Level int `yaml:"level,omitempty"`
	// Exec is the executable to run, relative to the manifest directory.
	// Empty means the conventional binpass-<name>.
	Exec string `yaml:"exec,omitempty"`
	// Capabilities is the access the plugin requests.
	Capabilities Capabilities `yaml:"capabilities"`
}

// Capabilities is the access a plugin requests, and the whole of what the
// user is asked to approve.
//
// Every field denies by default. An absent list is an empty list, never a
// wildcard: a manifest that requests nothing must receive nothing, or the
// consent the user gave would not mean what it says.
// The JSON tags are not decoration: capabilities travel to a child binpass
// as JSON in the environment, and a field that failed to decode would silently
// become an empty grant. The two encodings must name the fields identically.
type Capabilities struct {
	// ReadPaths are the entry patterns the plugin may list and read.
	ReadPaths []string `yaml:"read_paths,omitempty" json:"read_paths,omitempty"`
	// WritePaths are the entry patterns the plugin may create or modify.
	WritePaths []string `yaml:"write_paths,omitempty" json:"write_paths,omitempty"`
	// Decrypt allows access to plaintext. Without it a plugin may learn
	// that an entry exists but never what it contains.
	Decrypt bool `yaml:"decrypt,omitempty" json:"decrypt,omitempty"`
	// Network is the host allowlist. An empty list forbids the network.
	Network []string `yaml:"network,omitempty" json:"network,omitempty"`
	// Exec is the external binaries the plugin may invoke.
	Exec []string `yaml:"exec,omitempty" json:"exec,omitempty"`
}

// ErrInvalidManifest reports a manifest that cannot be trusted to describe a
// plugin.
var ErrInvalidManifest = errors.New("plugin: invalid manifest")

// ParseManifest reads and validates a manifest.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	// KnownFields is deliberate: a typo in a capability key would otherwise
	// be silently dropped, and the plugin would appear to request less than
	// its author wrote. Failing loudly is the only safe reading.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate reports whether the manifest is well formed.
func (m *Manifest) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidManifest)
	}
	if !validName(m.Name) {
		return fmt.Errorf("%w: name %q must be lowercase letters, digits and dashes",
			ErrInvalidManifest, m.Name)
	}
	if m.API == 0 {
		return fmt.Errorf("%w: api is required; this binpass speaks api %d",
			ErrInvalidManifest, APIVersion)
	}
	if m.API != APIVersion {
		return fmt.Errorf("%w: plugin %q needs api %d, this binpass speaks %d",
			ErrInvalidManifest, m.Name, m.API, APIVersion)
	}
	if m.Level == 0 {
		m.Level = 1
	}
	if m.Level < 1 || m.Level > 3 {
		return fmt.Errorf("%w: level %d is not one of 1, 2 or 3", ErrInvalidManifest, m.Level)
	}
	// Reading plaintext without being allowed to read any entry is a
	// contradiction, and it is the kind that hides a mistake in the
	// manifest rather than an intent.
	if m.Capabilities.Decrypt && len(m.Capabilities.ReadPaths) == 0 {
		return fmt.Errorf("%w: %q requests decrypt but no read_paths, so it could decrypt nothing",
			ErrInvalidManifest, m.Name)
	}
	for _, h := range m.Capabilities.Network {
		if strings.ContainsAny(h, "/ ") {
			return fmt.Errorf("%w: network entry %q must be a host, not a URL",
				ErrInvalidManifest, h)
		}
	}
	return nil
}

// validName reports whether a plugin name is safe to use as a subcommand and
// as a path element. Anything outside this set could produce a command that
// shadows a builtin or a file name that escapes the plugin directory.
func validName(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// Command returns the subcommand name the plugin provides.
func (m *Manifest) Command() string { return m.Name }

// Binary returns the executable name relative to the plugin directory.
func (m *Manifest) Binary() string {
	if m.Exec != "" {
		return m.Exec
	}
	return "binpass-" + m.Name
}

// Sensitive reports whether the manifest asks for anything that deserves a
// second look at install time.
func (m *Manifest) Sensitive() bool {
	return m.Capabilities.Decrypt ||
		len(m.Capabilities.Network) > 0 ||
		len(m.Capabilities.WritePaths) > 0 ||
		len(m.Capabilities.Exec) > 0
}

// Summary renders the capabilities for human approval.
//
// It states what access means in terms of consequence rather than repeating
// the YAML keys: someone deciding whether to trust a plugin needs to know
// that it will see their passwords, not that decrypt is true.
func (m *Manifest) Summary() string {
	var b strings.Builder
	c := m.Capabilities

	if c.Decrypt {
		b.WriteString("  ! CAN READ YOUR PASSWORDS IN PLAINTEXT\n")
	}
	if len(c.ReadPaths) > 0 {
		fmt.Fprintf(&b, "  reads:   %s\n", strings.Join(c.ReadPaths, ", "))
	} else {
		b.WriteString("  reads:   nothing\n")
	}
	if len(c.WritePaths) > 0 {
		fmt.Fprintf(&b, "  writes:  %s\n", strings.Join(c.WritePaths, ", "))
	} else {
		b.WriteString("  writes:  nothing\n")
	}
	if len(c.Network) > 0 {
		fmt.Fprintf(&b, "  network: %s\n", strings.Join(c.Network, ", "))
	} else {
		b.WriteString("  network: none\n")
	}
	if len(c.Exec) > 0 {
		fmt.Fprintf(&b, "  runs:    %s\n", strings.Join(c.Exec, ", "))
	}
	return b.String()
}
