package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runManTo executes `man <dir>` against a freshly built root command, the
// way Execute would dispatch it, and returns the directory the pages landed
// in. The root is rebuilt per call because its name is chosen from argv[0]
// at construction time.
func runManTo(t *testing.T, dir string) {
	t.Helper()
	app := &App{Cfg: config.Config{Dir: t.TempDir()}, Out: discard{}, Err: discard{}}
	root := newRootCmd(app, "test", "none", "unknown")
	root.SetArgs([]string{"man", dir})
	require.NoError(t, root.Execute())
}

// discard swallows command output; the man command writes files, not stdout.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// TestMan_GeneratesPagePerCommand verifies the manual covers every visible
// subcommand and nothing else: the hidden `man` command must not document
// itself, and no page may exist for a command the binary does not have.
func TestMan_GeneratesPagePerCommand(t *testing.T) {
	dir := t.TempDir()
	runManTo(t, dir)

	app := &App{Cfg: config.Config{Dir: t.TempDir()}, Out: discard{}, Err: discard{}}
	root := newRootCmd(app, "test", "none", "unknown")

	// Count every command the tree will document, mirroring the filter
	// cobra/doc applies: visible, runnable-or-parent commands only.
	var count func(c *cobra.Command) int
	count = func(c *cobra.Command) int {
		n := 1
		for _, sub := range c.Commands() {
			if sub.IsAvailableCommand() && !sub.IsAdditionalHelpTopicCommand() {
				n += count(sub)
			}
		}
		return n
	}
	want := count(root)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	// Every page is named after a command path: binpass.1 for the root,
	// binpass-<sub>[<-sub>].1 below it.
	nameRe := regexp.MustCompile(`^binpass(-[a-z0-9]+)*\.1$`)
	pages := map[string]bool{}
	for _, e := range entries {
		assert.Regexp(t, nameRe, e.Name())
		assert.False(t, e.IsDir())
		pages[e.Name()] = true
	}

	// One page per visible command in the whole tree, plus the root
	// itself; a count mismatch means either a command lost its page or a
	// hidden one leaked into the documented surface.
	assert.Len(t, pages, want)

	// Spot-check the surface: the root page, a pass-compatible command,
	// and a binpass-only one. A page for the hidden generator would mean
	// it leaked into the documented command surface.
	for _, name := range []string{"binpass.1", "binpass-init.1", "binpass-generate.1", "binpass-completion.1"} {
		assert.Contains(t, pages, name, "expected a man page for %s", name)
	}
	assert.NotContains(t, pages, "binpass-man.1")
}

// TestMan_RootPageContent checks the generated roff is a real man page: a
// .TH header with the right title, section and source, and a SYNOPSIS the
// `man` command can render from.
func TestMan_RootPageContent(t *testing.T) {
	dir := t.TempDir()
	runManTo(t, dir)

	page, err := os.ReadFile(filepath.Join(dir, "binpass.1"))
	require.NoError(t, err)
	text := string(page)

	assert.Contains(t, text, `.TH "BINPASS" "1"`)
	assert.Contains(t, text, `"binpass test"`)
	assert.Contains(t, text, `"User Commands"`)
	assert.Contains(t, text, "SYNOPSIS")
	assert.Contains(t, text, "pass(1)-compatible password manager")

	// The flag defaults are the documented ones, not wherever the machine
	// generating the page keeps its files: the store default is pass's own
	// location, and no identity is configured out of the box.
	assert.Contains(t, text, `\fB--store\fP="~/.password-store"`)
	assert.Contains(t, text, `\fB--identity\fP=""`)
	assert.NotContains(t, text, os.Getenv("HOME"))
}

// TestMan_FilesAreWorldReadable pins the 0644 mode: cobra creates pages with
// os.Create, and a package should not ship documentation whose readability
// depends on the umask of whatever built it.
func TestMan_FilesAreWorldReadable(t *testing.T) {
	dir := t.TempDir()
	runManTo(t, dir)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for _, e := range entries {
		info, err := e.Info()
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), e.Name())
	}
}

// TestMan_NameFollowsArgv0 covers the pass shim: binpass installed as `pass`
// must produce pass.1, not a page named after the binary underneath. A man
// page named binpass.1 installed as pass documents a command that is not
// there, exactly like a completion script generated under the wrong name.
func TestMan_NameFollowsArgv0(t *testing.T) {
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })

	dir := t.TempDir()
	os.Args = []string{"/run/current-system/sw/bin/pass"}
	runManTo(t, dir)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		assert.True(t, strings.HasPrefix(e.Name(), "pass"), "page %s is not named after pass", e.Name())
	}
	assert.Contains(t, names, "pass.1")
	assert.NotContains(t, names, "binpass.1")
}

// TestMan_PagesIgnoreTheBuildEnvironment pins the property that makes
// build-time generation shippable: the pages must be byte-identical no
// matter whose machine built them. Without the scrub, a CI runner, a nix
// sandbox and a developer's laptop would each document their own
// ~/.password-store and whatever identity their config file names.
func TestMan_PagesIgnoreTheBuildEnvironment(t *testing.T) {
	// A fixed date keeps the comparison about content, not the clock.
	require.NoError(t, os.Setenv("SOURCE_DATE_EPOCH", "315532800"))
	t.Cleanup(func() { _ = os.Unsetenv("SOURCE_DATE_EPOCH") })

	// Env manipulations here cannot use t.Setenv: each value must be
	// back to a clean state before the second run, and t.Setenv only
	// restores at test end.
	set := func(k, v string) {
		old, had := os.LookupEnv(k)
		if had {
			t.Cleanup(func() { _ = os.Setenv(k, old) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(k) })
		}
		require.NoError(t, os.Setenv(k, v))
	}
	unset := func(k string) {
		if _, had := os.LookupEnv(k); had {
			// An empty value, not a removal: the true original is
			// restored by the set() cleanup registered before this
			// one; this only neutralises the polluted value for the
			// clean run below.
			t.Cleanup(func() { t.Setenv(k, "") })
		}
		require.NoError(t, os.Unsetenv(k))
	}

	generate := func(pollute bool) string {
		home := t.TempDir()
		set("HOME", home)
		set("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		// No config file exists in either run; only the environment differs.
		set("BINPASS_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
		if pollute {
			set("PASSWORD_STORE_DIR", "/build-machine/store")
			set("BINPASS_IDENTITY", "/build-machine/key.age")
			set("BINPASS_THEME", "gruvbox")
		} else {
			// The polluted values are still set from the run above;
			// the clean run has to remove them, not skip setting them.
			unset("PASSWORD_STORE_DIR")
			unset("BINPASS_IDENTITY")
			unset("BINPASS_THEME")
		}

		cfg, err := config.Load()
		require.NoError(t, err)
		dir := t.TempDir()
		root := newRootCmd(NewApp(cfg), "test", "none", "unknown")
		root.SetArgs([]string{"man", dir})
		require.NoError(t, root.Execute())
		return dir
	}

	polluted := generate(true)
	clean := generate(false)

	pollutedPages := map[string]string{}
	for _, name := range pageFiles(t, polluted) {
		pollutedPages[name] = readPage(t, polluted, name)
	}
	require.NotEmpty(t, pollutedPages)

	for name, want := range pollutedPages {
		assert.Equal(t, want, readPage(t, clean, name), "page %s differs between build environments", name)
	}
}

// pageFiles lists the generated pages in dir.
func pageFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// readPage returns the contents of a single generated page.
func readPage(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err)
	return string(b)
}

// TestManPageFileMirrorsCobraNaming keeps the local name derivation in step
// with what cobra/doc actually writes; the chmod pass depends on it matching.
func TestManPageFileMirrorsCobraNaming(t *testing.T) {
	root := &cobra.Command{Use: "binpass"}
	sub := &cobra.Command{Use: "otp [entry]"}
	root.AddCommand(sub)

	assert.Equal(t, "binpass.1", manPageFile(root))
	// CommandPath drops the arguments and joins with spaces; the separator
	// cobra uses for files is the dash.
	assert.Equal(t, "binpass-otp.1", manPageFile(sub))
}
