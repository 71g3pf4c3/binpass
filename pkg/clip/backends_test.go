package clip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPasteNeverInvokesAWriter guards the bug where the Wayland backend was
// registered with an empty pasteArgs and wl-copy as its only binary: reading
// the clipboard then ran `wl-copy` with no input, wiping the user's clipboard
// instead of returning its contents.
func TestPasteNeverInvokesAWriter(t *testing.T) {
	writers := map[string]bool{"wl-copy": true, "pbcopy": true}

	for _, b := range backends("clipboard") {
		tl, ok := b.(*tool)
		if !ok {
			continue
		}
		require.NotEmpty(t, tl.bin, "%s: the paste binary must be set", tl.name)
		require.NotEmpty(t, tl.copyBin, "%s: the copy binary must be set", tl.name)
		assert.False(t, writers[tl.bin],
			"%s reads the clipboard with %q, which writes it", tl.name, tl.bin)
	}
}

func TestWaylandIsPreferredOverX11(t *testing.T) {
	// A Wayland session commonly exports DISPLAY too, via Xwayland. Choosing
	// xclip there would write to the compatibility layer, and the secret
	// would never reach the real clipboard.
	all := backends("clipboard")
	require.NotEmpty(t, all)
	assert.Equal(t, "wl-clipboard", all[0].Name())
}

func TestSelectionReachesEveryBackend(t *testing.T) {
	for _, b := range backends("primary") {
		switch v := b.(type) {
		case *tool:
			joined := ""
			for _, a := range append(v.copyArgs, v.pasteArgs...) {
				joined += a + " "
			}
			if v.name != "pbcopy" {
				assert.Contains(t, joined, "primary", "%s ignores the selection", v.name)
			}
		case *wlClipboard:
			assert.Equal(t, []string{"--primary"}, wlCopyArgs(v.selection))
		}
	}
}
