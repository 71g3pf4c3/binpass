package remote

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckPathAcceptsOrdinaryEntries(t *testing.T) {
	for _, p := range []string{
		"alice.age",
		"github.com/alice.gpg",
		"a/b/c/deep.age",
		"weird name with spaces.gpg",
		"unicode/пароль.age",
		"dots.in.the.name.gpg",
		"a/../b.age", // resolves to b.age, still inside the store
	} {
		assert.NoError(t, CheckPath(p), "%q is a legitimate store path", p)
	}
}

func TestCheckPathRejectsEscapes(t *testing.T) {
	for _, p := range []string{
		"",
		"..",
		"../outside.age",
		"../../../../etc/passwd",
		"a/../../outside.age",
		"/etc/passwd",
		"/absolute.age",
		`\windows\style.age`,
		`..\..\outside.age`,
		"a\x00b.age",
	} {
		assert.ErrorIs(t, CheckPath(p), ErrUnsafePath, "%q must be refused", p)
	}
}

// FuzzCheckPath asserts the property the callers depend on: any path CheckPath
// accepts stays inside the store root once joined onto it. A remote controls
// these strings, so this is the boundary that keeps a hostile listing from
// writing anywhere on the filesystem.
func FuzzCheckPath(f *testing.F) {
	for _, seed := range []string{
		"alice.age",
		"github.com/alice.gpg",
		"../escape.age",
		"../../../../etc/passwd",
		"/absolute.age",
		`..\windows.age`,
		"a/../b.age",
		"a/./b.age",
		"...",
		"..a/b.age",
		"a//b.age",
		"a/b/../../../c.age",
		"\x00",
	} {
		f.Add(seed)
	}

	root := filepath.Clean("/store")
	f.Fuzz(func(t *testing.T, p string) {
		if CheckPath(p) != nil {
			return
		}
		joined := filepath.Clean(filepath.Join(root, p))
		require.True(t,
			joined == root || strings.HasPrefix(joined, root+string(filepath.Separator)),
			"CheckPath accepted %q, which resolves to %q, outside %q", p, joined, root)
	})
}
