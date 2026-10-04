// Command testreport renders a `go test -json` event stream as the plain
// `go test` output a developer expects, and appends a loud warning when
// tests were skipped because an external tool is missing from PATH.
//
// Why this exists: the golden compatibility suite and the sync, tomb and
// importer integration tests all skip when their reference tools (pass, gpg,
// git, rclone, restic, cryptsetup) are not installed. Quiet `go test` output
// hides skips entirely, so a green run on a bare machine proves nothing about
// pass(1) compatibility while looking complete. The reporter keeps passing
// runs byte-for-byte as quiet as before, but ends a run with skips in it by
// naming every missing tool, the suites that skipped because of it, and what
// therefore remains unproven.
//
// The reporter never fails the run: it exits 0 even when it printed a
// warning, so the exit code of the pipeline stays whatever `go test`
// returned. Skips are visibility, not gating.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// modulePath is stripped from package names so the warning speaks in the
// relative paths used throughout the repository's docs.
const modulePath = "github.com/71g3pf4c3/binpass/"

// event is one test2json record as emitted by `go test -json`. Unknown
// actions and extra fields (Go has grown several since the format appeared)
// are ignored rather than rejected, so a newer toolchain's events degrade to
// unrendered instead of breaking the runner.
type event struct {
	Action     string `json:"Action"`
	Package    string `json:"Package"`
	ImportPath string `json:"ImportPath"`
	Test       string `json:"Test"`
	Output     string `json:"Output"`
}

// key identifies the test a buffered chunk of output belongs to.
func key(pkg, test string) string { return pkg + "\x00" + test }

// missingTool matches the `<file>.go:<line>:` lines the testing package
// prefixes t.Skip messages with, and extracts the tool the test decided it
// cannot live without. Anchoring on the file:line prefix keeps a passing
// test that merely logs the phrase "not on PATH" from being counted.
//
// The wording is the repository-wide convention for LookPath guards:
// "<tool> not on PATH" and "<tool> not found on PATH".
var missingTool = regexp.MustCompile(`^\s*\w[\w./-]*\.go:\d+: ([A-Za-z0-9_.-]+) not (?:found )?on PATH\b`)

// unproven says what a suite can no longer vouch for when its tool-dependent
// tests skip. Packages missing from the table get no unproven line rather
// than a guess, so a new suite still shows its skips — just without prose.
var unproven = map[string]string{
	"internal/cli/golden": "byte-for-byte output compatibility with pass(1)",
	"pkg/crypto":          "GPG interop with pass(1)",
	"pkg/importer":        "importing stores exported by real pass",
	"internal/cli":        "the pass-import and sync commands end to end",
	"pkg/remote":          "sync transports (git, restic, rclone remotes)",
	"pkg/vcs":             "git-backed store versioning",
	"pkg/tomb":            "tomb/LUKS integration with real cryptsetup",
	"internal/tui":        "git-dependent TUI flows",
}

// reporter is the streaming renderer. Output belonging to a passing or
// skipped test is buffered and dropped (that is what quiet `go test` does);
// output of a failing test is flushed when its failure event arrives, so
// failures still appear as the run goes.
type reporter struct {
	out io.Writer
	// err receives lines that are not valid events; it is a separate stream
	// so a broken run cannot smuggle tool output into the test summary.
	err io.Writer
	// bufs accumulates test-attributed output until the test's terminal event.
	bufs map[string]*strings.Builder
	// skipped maps the missing tool to its per-package skip counts.
	skipped map[string]map[string]int
}

func newReporter(out io.Writer) *reporter {
	return &reporter{out: out, err: os.Stderr, bufs: map[string]*strings.Builder{}}
}

// handleLine processes one JSON event line. Lines that do not parse as
// events are echoed to stderr untouched: `go test -json` guarantees JSON on
// stdout, so anything else is tool-level output that must not be swallowed.
func (r *reporter) handleLine(line []byte) {
	var ev event
	if err := json.Unmarshal(line, &ev); err != nil {
		fmt.Fprintln(r.err, string(line))
		return
	}

	switch ev.Action {
	case "output", "build-output":
		// Package-level output (the "ok pkg" summaries, build failures,
		// panics) is what quiet `go test` shows, so it passes straight
		// through. Test-level output is buffered until the verdict is known.
		// The one exception is the bare "PASS" the test binary prints: plain
		// `go test` filters it out, and keeping it would double the output
		// of an unchanged run.
		if ev.Test == "" {
			if ev.Action == "output" && ev.Output == "PASS\n" {
				return
			}
			fmt.Fprint(r.out, ev.Output)
			return
		}
		b := r.bufs[key(ev.Package, ev.Test)]
		if b == nil {
			b = &strings.Builder{}
			r.bufs[key(ev.Package, ev.Test)] = b
		}
		b.WriteString(ev.Output)

	case "pass":
		delete(r.bufs, key(ev.Package, ev.Test))

	case "fail":
		if ev.Test != "" {
			r.dump(key(ev.Package, ev.Test))
		}

	case "skip":
		if ev.Test != "" {
			r.noteSkip(ev.Package, key(ev.Package, ev.Test))
			delete(r.bufs, key(ev.Package, ev.Test))
		}
	}
}

// dump prints the buffered output of a finished test, minus the `=== RUN`
// style bookkeeping lines that only verbose mode shows.
func (r *reporter) dump(k string) {
	b := r.bufs[k]
	if b == nil {
		return
	}
	delete(r.bufs, k)
	for _, line := range strings.SplitAfter(b.String(), "\n") {
		if strings.HasPrefix(line, "=== RUN") ||
			strings.HasPrefix(line, "=== CONT") ||
			strings.HasPrefix(line, "=== PAUSE") ||
			strings.HasPrefix(line, "=== NAME") {
			continue
		}
		fmt.Fprint(r.out, line)
	}
}

// noteSkip inspects a skipped test's buffered messages for a missing-tool
// pattern and records the tool and package if one matches.
func (r *reporter) noteSkip(pkg, k string) {
	b := r.bufs[k]
	if b == nil {
		return
	}
	for _, line := range strings.Split(b.String(), "\n") {
		if m := missingTool.FindStringSubmatch(line); m != nil {
			if r.skipped == nil {
				r.skipped = map[string]map[string]int{}
			}
			if r.skipped[m[1]] == nil {
				r.skipped[m[1]] = map[string]int{}
			}
			r.skipped[m[1]][pkg]++
			return
		}
	}
}

// flush prints output of tests that never reached a verdict — a stream cut
// short by a signal, for instance. Dropping it would hide a failure.
func (r *reporter) flush() {
	for _, k := range sortedKeys(r.bufs) {
		r.dump(k)
	}
}

// warn prints the missing-tools summary. Nothing is printed when no
// tool-dependent test skipped, so a complete run stays byte-for-byte as
// quiet as plain `go test`.
func (r *reporter) warn() {
	if len(r.skipped) == 0 {
		return
	}

	fmt.Fprintln(r.out)
	fmt.Fprintln(r.out, "================================================================================")
	fmt.Fprintln(r.out, "  WARNING: some tests were SKIPPED because external tools are missing from PATH.")
	fmt.Fprintln(r.out, "  Skips are not failures, but this run proves less than a complete one:")

	for _, tool := range sortedKeys(r.skipped) {
		fmt.Fprintf(r.out, "\n  %s\n", tool)
		for _, pkg := range sortedKeys(r.skipped[tool]) {
			n := r.skipped[tool][pkg]
			fmt.Fprintf(r.out, "    skipped: %s (%d test%s)\n", relPath(pkg), n, plural(n))
		}
		// One tool may drag several suites down with it, so each affected
		// package states what it can no longer vouch for.
		for _, pkg := range sortedKeys(r.skipped[tool]) {
			if what, ok := unproven[relPath(pkg)]; ok {
				fmt.Fprintf(r.out, "    unproven: %s\n", what)
			}
		}
	}

	fmt.Fprintln(r.out)
	fmt.Fprintln(r.out, "  Run the tests inside `nix develop` (all tools present) or install")
	fmt.Fprintln(r.out, "  the tools above to close the gap.")
	fmt.Fprintln(r.out, "================================================================================")
}

func main() {
	r := newReporter(os.Stdout)

	// Golden-suite diffs are single output events and can be far larger than
	// bufio.Scanner's 64 KiB default.
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		r.handleLine(sc.Bytes())
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "testreport: reading events: %v\n", err)
		os.Exit(1)
	}
	r.flush()
	r.warn()
}

// relPath strips the module prefix so the warning names packages the way the
// repository's docs do.
func relPath(pkg string) string {
	return strings.TrimPrefix(pkg, modulePath)
}

// plural keeps "(1 test)" from reading as a typo.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// sortedKeys returns map keys in a stable order so the warning block is
// reproducible.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
