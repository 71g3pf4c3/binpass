package cli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunType covers `binpass type`: the entry's field is sent as
// keystrokes, with the secret arriving over stdin rather than argv.
func TestRunType(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "site/login", "hunter2\nusername: jane\n")

	dir := t.TempDir()
	typingToolStub(t, dir)
	t.Setenv("PATH", dir)

	require.NoError(t, app.runType(context.Background(), "site/login", "password", 0))
	assert.Equal(t, "hunter2", typedText(t))

	require.NoError(t, app.runType(context.Background(), "site/login", "username", 0))
	assert.Equal(t, "jane", typedText(t))
}
