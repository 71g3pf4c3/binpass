package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
)

// Environment variables that make up the plugin contract.
const (
	// EnvAPI is the contract version; plugins should refuse an unknown one.
	EnvAPI = "BINPASS_API"
	// EnvBin is the absolute path back to binpass, so a plugin never has to
	// guess how it was invoked or find it on PATH.
	EnvBin = "BINPASS_BIN"
	// EnvStore is the password store directory.
	EnvStore = "BINPASS_STORE"
	// EnvVersion is the binpass version.
	EnvVersion = "BINPASS_VERSION"
	// EnvPluginDir is the plugin's own directory, for its data files.
	EnvPluginDir = "BINPASS_PLUGIN_DIR"
	// EnvPluginName identifies the running plugin to the child binpass.
	EnvPluginName = "BINPASS_PLUGIN"
	// EnvCapabilities carries the granted capabilities as JSON, which is
	// how a child binpass learns what it may do on the plugin's behalf.
	EnvCapabilities = "BINPASS_PLUGIN_CAPABILITIES"
)

// Runner executes plugins.
type Runner struct {
	// Bin is the absolute path to the binpass executable.
	Bin string
	// StoreDir is the password store directory.
	StoreDir string
	// Version is the binpass version string.
	Version string
	// Stdin, Stdout and Stderr are the plugin's streams.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// Run executes a plugin with the contract environment applied.
//
// The plugin inherits the user's environment, minus anything that would let a
// nested binpass be pointed elsewhere, plus the contract variables and the
// capabilities it was granted.
func (r *Runner) Run(ctx context.Context, p *Plugin, args []string) error {
	if p.Path == "" {
		return fmt.Errorf("plugin: %s has nothing to execute", p.Manifest.Name)
	}
	cmd := exec.CommandContext(ctx, p.Path, args...) //nolint:gosec // the path comes from plugin discovery, and running it is the point.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = r.Stdin, r.Stdout, r.Stderr
	cmd.Dir = p.Dir

	env, err := r.env(p)
	if err != nil {
		return err
	}
	cmd.Env = env
	applyIsolation(cmd)

	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// env builds the plugin environment.
func (r *Runner) env(p *Plugin) ([]string, error) {
	env := append(sanitiseEnv(os.Environ()),
		EnvAPI+"="+strconv.Itoa(APIVersion),
		EnvBin+"="+r.Bin,
		EnvStore+"="+r.StoreDir,
		EnvVersion+"="+r.Version,
		EnvPluginDir+"="+p.Dir,
		EnvPluginName+"="+p.Manifest.Name,
		// Scripts written for pass expect this name, and a plugin that
		// shells out to pass itself should reach the same store.
		"PASSWORD_STORE_DIR="+r.StoreDir,
	)
	// Only a plugin that declared a manifest carries a grant. Publishing an
	// empty one for an unmanaged plugin would tell the child binpass to
	// enforce a restriction the user never agreed to, and deny everything.
	if p.Managed {
		encoded, err := json.Marshal(p.Manifest.Capabilities)
		if err != nil {
			return nil, err
		}
		env = append(env, EnvCapabilities+"="+string(encoded))
	}
	return env, nil
}

// stripped are the variables removed from a plugin's environment.
//
// A plugin must not inherit an ambient capability grant from whatever
// invoked binpass, and it must not be able to redirect a nested binpass at
// another store by way of variables already in the environment. Both are set
// explicitly afterwards from values binpass controls.
var stripped = map[string]bool{
	EnvCapabilities:      true,
	EnvPluginName:        true,
	"PASSWORD_STORE_DIR": true,
	"BINPASS_STORE":      true,
}

// sanitiseEnv removes the variables a plugin must not inherit.
func sanitiseEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if k, _, ok := cut(kv, "="); ok && stripped[k] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// cut splits s around the first instance of sep.
func cut(s, sep string) (before, after string, found bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}

// ActiveCapabilities returns the capabilities in force for this process, the
// plugin they belong to, and whether any restriction applies at all.
//
// A binpass the user invoked directly is unrestricted. A binpass invoked
// through BINPASS_BIN by a plugin that declared a manifest carries that
// plugin's grant and enforces it.
//
// An unmanaged plugin, the bare executable on PATH, is deliberately not
// restricted. It could read the store directly without asking binpass at all,
// so refusing it through the callback would block nothing while breaking
// every straightforward plugin. Restriction is meaningful only where a
// manifest recorded what the user agreed to.
func ActiveCapabilities(getenv func(string) string) (caps Capabilities, name string, restricted bool) {
	name = getenv(EnvPluginName)
	if name == "" {
		return Capabilities{}, "", false
	}
	raw := getenv(EnvCapabilities)
	if raw == "" {
		return Capabilities{}, name, false
	}
	if err := json.Unmarshal([]byte(raw), &caps); err != nil {
		// Being told a plugin is running but not what it may do is not a
		// reason to allow everything.
		return Capabilities{}, name, true
	}
	return caps, name, true
}
