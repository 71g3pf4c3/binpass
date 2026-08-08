package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envOf returns a lookup function over a fixed environment.
func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDetectStyleFollowsLocaleAndTerm(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]string
		utf8   bool
		colour bool
	}{
		{"utf-8 locale and a terminal", map[string]string{"LC_ALL": "C.UTF-8", "TERM": "xterm"}, true, true},
		{"utf-8 via LANG", map[string]string{"LANG": "en_US.UTF-8", "TERM": "xterm"}, true, true},
		{"utf-8 spelled without a dash", map[string]string{"LANG": "en_US.utf8", "TERM": "xterm"}, true, true},
		{"C locale keeps ascii glyphs", map[string]string{"LC_ALL": "C", "TERM": "xterm"}, false, true},
		{"no locale at all", map[string]string{"TERM": "xterm"}, false, true},
		{"no terminal means no colour", map[string]string{"LC_ALL": "C.UTF-8"}, true, false},
		{"LC_ALL wins over LANG", map[string]string{"LC_ALL": "C", "LANG": "en_US.UTF-8", "TERM": "xterm"}, false, true},
		{"LC_CTYPE wins over LANG", map[string]string{"LC_CTYPE": "C.UTF-8", "LANG": "C", "TERM": "xterm"}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := detectStyle(envOf(tc.env))
			assert.Equal(t, tc.colour, s.colour)
			if tc.utf8 {
				assert.Equal(t, treeBranchUTF, s.branch)
			} else {
				assert.Equal(t, treeBranchASCII, s.branch)
			}
		})
	}
}

func TestRenderTreeUTF8WithColour(t *testing.T) {
	var buf bytes.Buffer
	names := []string{"a/b/c/deep", "a/b/other", "a/sibling", "root", "z/last"}
	require.NoError(t, renderTreeStyled(&buf, "Password Store", names, detectStyle(envOf(map[string]string{
		"LC_ALL": "C.UTF-8", "TERM": "xterm",
	}))))

	// This is byte for byte what `pass ls` prints for the same store.
	want := "Password Store\n" +
		"├── \x1b[01;34ma\x1b[0m\n" +
		"│\u00a0\u00a0 ├── \x1b[01;34mb\x1b[0m\n" +
		"│\u00a0\u00a0 │\u00a0\u00a0 ├── \x1b[01;34mc\x1b[0m\n" +
		"│\u00a0\u00a0 │\u00a0\u00a0 │\u00a0\u00a0 └── \x1b[00mdeep\x1b[0m\n" +
		"│\u00a0\u00a0 │\u00a0\u00a0 └── \x1b[00mother\x1b[0m\n" +
		"│\u00a0\u00a0 └── \x1b[00msibling\x1b[0m\n" +
		"├── \x1b[00mroot\x1b[0m\n" +
		"└── \x1b[01;34mz\x1b[0m\n" +
		"    └── \x1b[00mlast\x1b[0m\n"
	assert.Equal(t, want, buf.String())
}

func TestRenderTreeASCIIWithoutColour(t *testing.T) {
	var buf bytes.Buffer
	names := []string{"a/c", "root"}
	require.NoError(t, renderTreeStyled(&buf, "Password Store", names, detectStyle(envOf(nil))))

	want := "Password Store\n" +
		"|-- a\n" +
		"|   `-- c\n" +
		"`-- root\n"
	assert.Equal(t, want, buf.String(), "without a UTF-8 locale or TERM, tree falls back to plain ASCII")
}

func TestRenderTreeWithoutHeading(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, renderTreeStyled(&buf, "", []string{"only"}, detectStyle(envOf(nil))))
	assert.Equal(t, "`-- only\n", buf.String(), "find prints no heading")
}

func TestRenderTreeEmpty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, renderTreeStyled(&buf, "Password Store", nil, detectStyle(envOf(nil))))
	assert.Equal(t, "Password Store\n", buf.String())
}
