package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectLine(t *testing.T) {
	lines := []string{"hunter2", "url: https://example.com", "", "username: alice"}

	got, err := selectLine(lines, 1)
	require.NoError(t, err)
	assert.Equal(t, "hunter2", got, "line 1 is the password")

	got, err = selectLine(lines, 2)
	require.NoError(t, err)
	assert.Equal(t, "url: https://example.com", got)

	got, err = selectLine(lines, 4)
	require.NoError(t, err)
	assert.Equal(t, "username: alice", got)
}

func TestSelectLineRejectsMissingLines(t *testing.T) {
	lines := []string{"hunter2", "", "third"}

	_, err := selectLine(lines, 99)
	assert.ErrorContains(t, err, "no password to put on the clipboard at line 99")

	_, err = selectLine(lines, 2)
	assert.ErrorContains(t, err, "line 2", "a blank line has nothing to copy")

	_, err = selectLine(lines, 0)
	assert.ErrorContains(t, err, "not a number")

	_, err = selectLine(nil, 1)
	assert.Error(t, err)
}
