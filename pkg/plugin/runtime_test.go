package plugin_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runPlugin executes a shell stub as a plugin and returns what it printed.
func runPlugin(t *testing.T, p *plugin.Plugin, script string, args ...string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the shebang convention is POSIX-only")
	}
	require.NoError(t, os.WriteFile(p.Path, []byte(script), 0o700)) //nolint:gosec // a test stub.

	var out bytes.Buffer
	r := &plugin.Runner{
		Bin:      "/usr/bin/binpass",
		StoreDir: "/tmp/store",
		Version:  "9.9.9",
		Stdout:   &out,
		Stderr:   &out,
	}
	require.NoError(t, r.Run(context.Background(), p, args))
	return out.String()
}

// stub returns a plugin rooted in a temporary directory.
func stub(t *testing.T, managed bool, caps plugin.Capabilities) *plugin.Plugin {
	t.Helper()
	dir := t.TempDir()
	return &plugin.Plugin{
		Manifest: &plugin.Manifest{
			Name: "demo", API: plugin.APIVersion, Level: plugin.LevelExec,
			Capabilities: caps,
		},
		Path:    filepath.Join(dir, "binpass-demo"),
		Dir:     dir,
		Managed: managed,
	}
}

func TestRunnerExportsTheContract(t *testing.T) {
	p := stub(t, false, plugin.Capabilities{})
	got := runPlugin(t, p, "#!/bin/sh\nenv | sort\n")

	assert.Contains(t, got, plugin.EnvAPI+"=1")
	assert.Contains(t, got, plugin.EnvBin+"=/usr/bin/binpass")
	assert.Contains(t, got, plugin.EnvStore+"=/tmp/store")
	assert.Contains(t, got, plugin.EnvVersion+"=9.9.9")
	assert.Contains(t, got, plugin.EnvPluginName+"=demo")
	// Scripts written for pass reach for this name and must find the same
	// store binpass is using.
	assert.Contains(t, got, "PASSWORD_STORE_DIR=/tmp/store")
}

func TestRunnerPassesArgumentsUntouched(t *testing.T) {
	p := stub(t, false, plugin.Capabilities{})
	got := runPlugin(t, p, "#!/bin/sh\necho \"$*\"\n", "--flag", "value", "-x")

	assert.Equal(t, "--flag value -x\n", got)
}

// TestGrantSurvivesTheEnvironment is the round trip that a missing JSON tag
// once broke: capabilities are marshalled into the environment here and
// unmarshalled by the child binpass, and a field that failed to decode would
// silently become an empty grant that denies everything.
func TestGrantSurvivesTheEnvironment(t *testing.T) {
	caps := plugin.Capabilities{
		ReadPaths:  []string{"work/**"},
		WritePaths: []string{"work/scratch/**"},
		Decrypt:    true,
		Network:    []string{"api.example.com"},
		Exec:       []string{"curl"},
	}
	p := stub(t, true, caps)
	got := runPlugin(t, p, "#!/bin/sh\necho \"$"+plugin.EnvCapabilities+"\"\n")

	// Feed the exported value back through the reader the child would use.
	decoded, name, restricted := plugin.ActiveCapabilities(func(k string) string {
		switch k {
		case plugin.EnvPluginName:
			return "demo"
		case plugin.EnvCapabilities:
			return strings.TrimSpace(got)
		}
		return ""
	})
	require.True(t, restricted)
	assert.Equal(t, "demo", name)
	assert.Equal(t, caps, decoded, "the grant must survive the round trip intact")
}

// TestUnmanagedPluginCarriesNoGrant records the deliberate asymmetry: a bare
// executable on PATH never had a manifest approved, and publishing an empty
// grant would tell the child binpass to enforce a restriction the user never
// agreed to, denying everything.
func TestUnmanagedPluginCarriesNoGrant(t *testing.T) {
	p := stub(t, false, plugin.Capabilities{})
	got := runPlugin(t, p, "#!/bin/sh\necho \"[$"+plugin.EnvCapabilities+"]\"\n")

	assert.Equal(t, "[]\n", got)
}

// TestForgedGrantIsStripped prevents a plugin from inheriting a capability
// claim planted in the environment of whatever launched binpass.
func TestForgedGrantIsStripped(t *testing.T) {
	t.Setenv(plugin.EnvCapabilities, `{"read_paths":["**"],"decrypt":true}`)
	t.Setenv(plugin.EnvPluginName, "impostor")

	p := stub(t, false, plugin.Capabilities{})
	got := runPlugin(t, p, "#!/bin/sh\necho \"caps=[$"+plugin.EnvCapabilities+"]\"\necho \"name=$"+plugin.EnvPluginName+"\"\n")

	assert.Contains(t, got, "caps=[]", "an inherited grant must not survive")
	assert.Contains(t, got, "name=demo", "the plugin's identity is set by binpass, not inherited")
}

// TestStoreCannotBeRedirected stops a plugin from being pointed at another
// store by a variable already in the environment.
func TestStoreCannotBeRedirected(t *testing.T) {
	t.Setenv("PASSWORD_STORE_DIR", "/somewhere/else")

	p := stub(t, false, plugin.Capabilities{})
	got := runPlugin(t, p, "#!/bin/sh\necho \"$PASSWORD_STORE_DIR\"\n")

	assert.Equal(t, "/tmp/store\n", got)
}

func TestRunnerReportsAMissingExecutable(t *testing.T) {
	p := &plugin.Plugin{
		Manifest: &plugin.Manifest{Name: "recipe", API: plugin.APIVersion, Level: plugin.LevelRecipe},
	}
	r := &plugin.Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}

	err := r.Run(context.Background(), p, nil)
	assert.ErrorContains(t, err, "nothing to execute")
}
