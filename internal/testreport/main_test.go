package main

import (
	"bytes"
	"strings"
	"testing"
)

// runReporter feeds a raw `go test -json` event stream through the reporter
// and returns everything it wrote, warning block and stderr forwarding
// included.
func runReporter(t *testing.T, lines ...string) string {
	t.Helper()
	var out bytes.Buffer
	r := newReporter(&out)
	r.err = &out
	for _, l := range lines {
		r.handleLine([]byte(l))
	}
	r.flush()
	r.warn()
	return out.String()
}

// okLine is the package summary a passing package emits; it must reach the
// terminal untouched.
const okLine = `{"Time":"t","Action":"output","Package":"github.com/71g3pf4c3/binpass/pkg/pwgen","Output":"ok  \tgithub.com/71g3pf4c3/binpass/pkg/pwgen\t0.001s\n"}`

// toolSkip is the event pair a `t.Skip("restic not on PATH")` produces.
const toolSkipOutput = `{"Time":"t","Action":"output","Package":"github.com/71g3pf4c3/binpass/pkg/remote","Test":"TestSnapshot","Output":"    restic_test.go:23: restic not on PATH\n"}`
const toolSkipEvent = `{"Time":"t","Action":"skip","Package":"github.com/71g3pf4c3/binpass/pkg/remote","Test":"TestSnapshot","Elapsed":0}`

func TestQuietPassingRunIsUnchanged(t *testing.T) {
	// The bare "PASS" the binary emits is filtered like plain `go test` does;
	// keeping it would double the output of every unchanged run.
	got := runReporter(t,
		`{"Time":"t","Action":"output","Package":"github.com/71g3pf4c3/binpass/pkg/pwgen","Output":"PASS\n"}`,
		okLine,
	)
	if got != "ok  \tgithub.com/71g3pf4c3/binpass/pkg/pwgen\t0.001s\n" {
		t.Fatalf("passing output was rewritten:\n%q", got)
	}
	if strings.Contains(got, "WARNING") {
		t.Fatal("warning printed for a run with no relevant skips")
	}
}

func TestFailingTestOutputIsShownWithoutVerboseNoise(t *testing.T) {
	got := runReporter(t,
		`{"Time":"t","Action":"output","Package":"p","Test":"TestX","Output":"=== RUN   TestX\n"}`,
		`{"Time":"t","Action":"output","Package":"p","Test":"TestX","Output":"    x_test.go:4: boom\n"}`,
		`{"Time":"t","Action":"output","Package":"p","Test":"TestX","Output":"--- FAIL: TestX (0.01s)\n"}`,
		`{"Time":"t","Action":"fail","Package":"p","Test":"TestX","Elapsed":0.01}`,
		okLine,
	)
	for _, want := range []string{"--- FAIL: TestX (0.01s)\n", "    x_test.go:4: boom\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("failure output missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "=== RUN") {
		t.Error("verbose bookkeeping leaked into quiet output")
	}
	if strings.Contains(got, "WARNING") {
		t.Error("a failure is loud enough; no skip warning expected")
	}
}

func TestToolSkipProducesWarningNamingToolAndSuite(t *testing.T) {
	got := runReporter(t, toolSkipOutput, toolSkipEvent, okLine)
	for _, want := range []string{
		"WARNING",
		"restic",
		"pkg/remote (1 test)",
		"sync transports (git, restic, rclone remotes)",
		"nix develop",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("warning missing %q in:\n%s", want, got)
		}
	}
	// The ok line for an unrelated package must survive around the block.
	if !strings.Contains(got, "ok  \tgithub.com/71g3pf4c3/binpass/pkg/pwgen") {
		t.Error("package summary lost")
	}
}

func TestNonToolSkipStaysSilent(t *testing.T) {
	got := runReporter(t,
		`{"Time":"t","Action":"output","Package":"github.com/71g3pf4c3/binpass/pkg/tomb","Test":"TestLUKS","Output":"    luks_linux_test.go:377: needs root: cryptsetup requires /dev/mapper/control\n"}`,
		`{"Time":"t","Action":"skip","Package":"github.com/71g3pf4c3/binpass/pkg/tomb","Test":"TestLUKS","Elapsed":0}`,
		`{"Time":"t","Action":"output","Package":"github.com/71g3pf4c3/binpass/pkg/tomb","Output":"PASS\n"}`,
	)
	if strings.Contains(got, "WARNING") {
		t.Fatalf("privilege-related skip raised the missing-tool warning:\n%s", got)
	}
}

func TestSameToolAcrossSuitesIsAggregated(t *testing.T) {
	got := runReporter(t,
		`{"Time":"t","Action":"output","Package":"github.com/71g3pf4c3/binpass/pkg/remote","Test":"TestA","Output":"    a_test.go:1: rclone not on PATH\n"}`,
		`{"Time":"t","Action":"skip","Package":"github.com/71g3pf4c3/binpass/pkg/remote","Test":"TestA","Elapsed":0}`,
		`{"Time":"t","Action":"output","Package":"github.com/71g3pf4c3/binpass/pkg/remote","Test":"TestB","Output":"    b_test.go:2: rclone not on PATH\n"}`,
		`{"Time":"t","Action":"skip","Package":"github.com/71g3pf4c3/binpass/pkg/remote","Test":"TestB","Elapsed":0}`,
		`{"Time":"t","Action":"output","Package":"github.com/71g3pf4c3/binpass/internal/cli","Test":"TestC","Output":"    c_test.go:3: rclone not on PATH\n"}`,
		`{"Time":"t","Action":"skip","Package":"github.com/71g3pf4c3/binpass/internal/cli","Test":"TestC","Elapsed":0}`,
	)
	for _, want := range []string{"pkg/remote (2 tests)", "internal/cli (1 test)"} {
		if !strings.Contains(got, want) {
			t.Errorf("aggregation missing %q in:\n%s", want, got)
		}
	}
}

func TestWordingVariantsAreRecognised(t *testing.T) {
	tests := []struct {
		name    string
		message string
		tool    string
	}{
		{"not on PATH", "gpg not on PATH", "gpg"},
		{"not found on PATH", "git not found on PATH", "git"},
		{"trailing reason", "pass not on PATH: no reference implementation to compare against", "pass"},
		{"plain message line", "gpg not on PATH", "gpg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runReporter(t,
				`{"Time":"t","Action":"output","Package":"github.com/71g3pf4c3/binpass/pkg/crypto","Test":"TestX","Output":"    x_test.go:9: `+tt.message+`\n"}`,
				`{"Time":"t","Action":"skip","Package":"github.com/71g3pf4c3/binpass/pkg/crypto","Test":"TestX","Elapsed":0}`,
			)
			if !strings.Contains(got, "\n  "+tt.tool+"\n") {
				t.Errorf("tool %q not reported in:\n%s", tt.tool, got)
			}
		})
	}
}

func TestLeftoverBufferIsFlushed(t *testing.T) {
	// A stream cut before the verdict must not swallow what was already said.
	got := runReporter(t,
		`{"Time":"t","Action":"output","Package":"p","Test":"TestHalf","Output":"    x_test.go:9: about to die\n"}`,
	)
	if !strings.Contains(got, "about to die") {
		t.Fatalf("unterminated test output dropped:\n%q", got)
	}
}

func TestUnparseableLineIsForwardedNotSwallowed(t *testing.T) {
	got := runReporter(t, "go: some tool-level complaint")
	if !strings.Contains(got, "some tool-level complaint") {
		t.Fatalf("non-JSON line lost:\n%q", got)
	}
}
