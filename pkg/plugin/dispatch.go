package plugin

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Prefix is the file name prefix that turns an executable into a subcommand.
const Prefix = "binpass-"

// Resolution is a successful match of command line arguments to a plugin.
type Resolution struct {
	// Plugin is the plugin that will run.
	Plugin *Plugin
	// Args are the arguments left for the plugin, after the ones consumed
	// to name it.
	Args []string
	// Command is the subcommand as the user typed it, for diagnostics.
	Command string
}

// Resolve maps command line arguments to a plugin, following the same rules
// kubectl uses, because they are the convention users already know.
//
// The longest match wins: with both binpass-cloud and binpass-cloud-sync
// installed, "binpass cloud sync now" runs the latter and passes it "now".
// Argument scanning stops at the first flag, so "binpass foo --bar baz" looks
// only for binpass-foo and hands it "--bar baz" untouched.
//
// Dashes in an argument become underscores in the file name, which is what
// lets a plugin be called "binpass foo-bar" while living in a file named
// binpass-foo_bar. Without that convention there would be no way to tell the
// separator between words from the separator between subcommands.
func (s Source) Resolve(args []string) (*Resolution, bool) {
	// Only leading non-flag arguments can name a plugin.
	var words []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			break
		}
		words = append(words, a)
	}

	for n := len(words); n > 0; n-- {
		// Both spellings of a plugin name collapse to the same canonical
		// form: the file binpass-foo_bar and the file binpass-foo-bar both
		// provide the command "foo bar", and the user may type it either
		// as one dashed word or as two.
		lookup := canonical(strings.Join(words[:n], "-"))
		p, err := s.Find(lookup)
		if err != nil {
			continue
		}
		return &Resolution{
			Plugin:  p,
			Args:    args[n:],
			Command: strings.Join(args[:n], " "),
		}, true
	}
	return nil, false
}

// Candidate is an executable that looks like a plugin, including the ones
// that cannot actually be used.
//
// Listing broken candidates is the whole value of the command: a plugin that
// silently does not appear because its bit is not set is a frustrating thing
// to debug, and the fix is to say so.
type Candidate struct {
	// Name is the subcommand the file would provide.
	Name string
	// Path is the file's location.
	Path string
	// Executable reports whether the file can actually be run.
	Executable bool
	// ShadowedBy names the file that takes precedence, if any.
	ShadowedBy string
	// ShadowsBuiltin names the builtin command this file cannot override.
	ShadowsBuiltin string
	// Managed reports whether binpass installed it, and therefore whether a
	// manifest governs what it may do.
	Managed bool
}

// Usable reports whether the candidate will run when its command is typed.
func (c Candidate) Usable() bool {
	return c.Executable && c.ShadowedBy == "" && c.ShadowsBuiltin == ""
}

// Candidates returns every plugin-shaped file found, in the order the search
// path was walked, annotated with what makes it unusable.
func (s Source) Candidates(builtins []string) []Candidate {
	builtin := make(map[string]bool, len(builtins))
	for _, b := range builtins {
		builtin[b] = true
	}

	var out []Candidate
	winner := map[string]string{}

	note := func(c Candidate) {
		if first, ok := winner[c.Name]; ok {
			c.ShadowedBy = first
		} else if c.Executable {
			winner[c.Name] = c.Path
		}
		if builtin[c.Name] {
			c.ShadowsBuiltin = c.Name
		}
		out = append(out, c)
	}

	for _, dir := range s.Dirs {
		for _, p := range discoverDir(dir) {
			if p.Path == "" {
				continue
			}
			note(Candidate{
				Name:       p.Manifest.Name,
				Path:       p.Path,
				Executable: executable(p.Path),
				Managed:    true,
			})
		}
	}
	if s.PathLookup {
		for _, c := range scanPath() {
			note(c)
		}
	}
	return out
}

// scanPath walks PATH for plugin-shaped files, including non-executable ones
// so that they can be reported rather than quietly ignored.
func scanPath() []Candidate {
	var out []Candidate
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		// Directory order is filesystem-dependent; sorting keeps the output
		// stable so that it can be diffed and tested.
		sort.Strings(names)

		for _, file := range names {
			name, ok := commandName(file)
			if !ok {
				continue
			}
			full := filepath.Join(dir, file)
			out = append(out, Candidate{
				Name:       name,
				Path:       full,
				Executable: executable(full),
			})
		}
	}
	return out
}

// commandName extracts the subcommand a file name provides, following the
// kubectl convention where underscores in the file become dashes in the
// command.
func commandName(file string) (string, bool) {
	if !strings.HasPrefix(file, Prefix) {
		return "", false
	}
	name := strings.TrimPrefix(file, Prefix)
	if runtime.GOOS == "windows" {
		// A .bat plugin is as legitimate as an .exe one, and neither
		// extension is part of the command the user types.
		for _, ext := range []string{".exe", ".bat", ".cmd", ".com"} {
			if strings.EqualFold(filepath.Ext(name), ext) {
				name = name[:len(name)-len(ext)]
				break
			}
		}
	}
	name = canonical(name)
	if name == "" || !validName(name) {
		return "", false
	}
	return name, true
}

// canonical reduces a plugin name to the single spelling everything compares
// against, so that a lookup and a file name cannot disagree about whether a
// separator was a dash or an underscore.
func canonical(name string) string { return strings.ReplaceAll(name, "_", "-") }
