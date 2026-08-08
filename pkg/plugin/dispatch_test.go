package plugin_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pathWith puts a directory of executables on PATH for one test, and returns
// a Source that looks only there. Nothing outside the temporary directory is
// touched, and PATH is restored by t.Setenv.
func pathWith(t *testing.T, files ...string) (plugin.Source, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the executable bit, and so this convention, is POSIX-only")
	}
	dir := t.TempDir()
	for _, f := range files {
		write(t, filepath.Join(dir, f), 0o755)
	}
	t.Setenv("PATH", dir)
	return plugin.Source{PathLookup: true}, dir
}

// write creates a runnable stub file.
func write(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), mode))
}

func TestResolveFindsAPlugin(t *testing.T) {
	src, _ := pathWith(t, "binpass-hello")

	got, ok := src.Resolve([]string{"hello"})
	require.True(t, ok)
	assert.Equal(t, "hello", got.Plugin.Manifest.Name)
	assert.Empty(t, got.Args)
}

// TestResolvePrefersTheLongestMatch pins the rule kubectl uses: with both a
// short and a long plugin installed, the most specific one wins. Getting this
// backwards would make binpass-cloud permanently shadow binpass-cloud-sync.
func TestResolvePrefersTheLongestMatch(t *testing.T) {
	src, _ := pathWith(t, "binpass-cloud", "binpass-cloud-sync")

	got, ok := src.Resolve([]string{"cloud", "sync", "now"})
	require.True(t, ok)
	assert.Equal(t, "cloud-sync", got.Plugin.Manifest.Name)
	assert.Equal(t, []string{"now"}, got.Args, "the consumed words must not reach the plugin")
	assert.Equal(t, "cloud sync", got.Command)
}

func TestResolveFallsBackToTheShorterMatch(t *testing.T) {
	src, _ := pathWith(t, "binpass-cloud")

	got, ok := src.Resolve([]string{"cloud", "sync", "now"})
	require.True(t, ok)
	assert.Equal(t, "cloud", got.Plugin.Manifest.Name)
	assert.Equal(t, []string{"sync", "now"}, got.Args)
}

// TestResolveStopsAtTheFirstFlag keeps flags out of the name search. Treating
// "--dry-run" as part of a plugin name would look for binpass-foo---dry-run,
// and, worse, could match a file crafted to be found that way.
func TestResolveStopsAtTheFirstFlag(t *testing.T) {
	src, _ := pathWith(t, "binpass-foo")

	got, ok := src.Resolve([]string{"foo", "--dry-run", "bar"})
	require.True(t, ok)
	assert.Equal(t, "foo", got.Plugin.Manifest.Name)
	assert.Equal(t, []string{"--dry-run", "bar"}, got.Args)
}

// TestResolveMapsDashesToUnderscores covers the convention that allows a
// multi-word command to exist at all: the file separates words with
// underscores so that dashes remain free to separate subcommands.
func TestResolveMapsDashesToUnderscores(t *testing.T) {
	src, _ := pathWith(t, "binpass-foo_bar")

	got, ok := src.Resolve([]string{"foo-bar"})
	require.True(t, ok)
	assert.Equal(t, "foo-bar", got.Plugin.Manifest.Name)
}

func TestResolveMissingPlugin(t *testing.T) {
	src, _ := pathWith(t, "binpass-hello")

	_, ok := src.Resolve([]string{"goodbye"})
	assert.False(t, ok)
}

// TestNonExecutableIsNotResolved is the counterpart to reporting it: a file
// without the bit set must not run, but must still be listed as a problem.
func TestNonExecutableIsNotResolved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the executable bit is POSIX-only")
	}
	dir := t.TempDir()
	write(t, filepath.Join(dir, "binpass-broken"), 0o644)
	t.Setenv("PATH", dir)
	src := plugin.Source{PathLookup: true}

	_, ok := src.Resolve([]string{"broken"})
	assert.False(t, ok, "a file without the executable bit must not be run")

	found := src.Candidates(nil)
	require.Len(t, found, 1)
	assert.False(t, found[0].Executable)
	assert.False(t, found[0].Usable(), "it must be reported as unusable, not hidden")
}

func TestCandidatesReportsShadowing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH shadowing is exercised on POSIX")
	}
	first, second := t.TempDir(), t.TempDir()
	write(t, filepath.Join(first, "binpass-dup"), 0o755)
	write(t, filepath.Join(second, "binpass-dup"), 0o755)
	t.Setenv("PATH", first+string(os.PathListSeparator)+second)

	found := plugin.Source{PathLookup: true}.Candidates(nil)
	require.Len(t, found, 2)

	assert.True(t, found[0].Usable())
	assert.Equal(t, filepath.Join(first, "binpass-dup"), found[0].Path)

	assert.False(t, found[1].Usable(), "the second copy is unreachable and must say so")
	assert.Equal(t, found[0].Path, found[1].ShadowedBy)
}

// TestCandidatesReportsBuiltinShadowing covers the trap where someone names a
// plugin after a real command and cannot work out why it never runs.
func TestCandidatesReportsBuiltinShadowing(t *testing.T) {
	src, _ := pathWith(t, "binpass-show")

	found := src.Candidates([]string{"show", "ls", "insert"})
	require.Len(t, found, 1)
	assert.Equal(t, "show", found[0].ShadowsBuiltin)
	assert.False(t, found[0].Usable())
}

func TestCandidatesIgnoresUnrelatedFiles(t *testing.T) {
	src, _ := pathWith(t, "binpass-real", "binpassnodash", "notbinpass-x", "binpass-")

	found := src.Candidates(nil)
	require.Len(t, found, 1)
	assert.Equal(t, "real", found[0].Name)
}
