package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConflictsListReportsNothingWhenClean(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alice", "hunter2\n")

	require.NoError(t, app.runConflictsList())
	assert.Contains(t, app.out.String(), "No conflicts.")
}

func TestConflictsListNamesTheOriginal(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "github.com/alice", "remote-secret\n")
	app.set(t, "github.com/alice.conflict-thinkpad-20260808T142233", "local-secret\n")

	require.NoError(t, app.runConflictsList())
	got := app.out.String()
	assert.Contains(t, got, "github.com/alice.conflict-thinkpad-20260808T142233")
	assert.Contains(t, got, "(conflict of github.com/alice)")
}

func TestConflictsDiffMasksPasswordsByDefault(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alice", "remote-secret\nurl: example.com\n")
	app.set(t, "alice.conflict-thinkpad-20260808T142233", "local-secret\n")

	require.NoError(t, app.runConflictsDiff("alice.conflict-thinkpad-20260808T142233", false))
	got := app.out.String()
	assert.NotContains(t, got, "local-secret", "the password line must be masked")
	assert.NotContains(t, got, "remote-secret")
	assert.Contains(t, got, "*")
	assert.Contains(t, got, "url: example.com", "non-password lines stay readable")
}

func TestConflictsDiffShowsSecretsOnRequest(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alice", "remote-secret\n")
	app.set(t, "alice.conflict-thinkpad-20260808T142233", "local-secret\n")

	require.NoError(t, app.runConflictsDiff("alice.conflict-thinkpad-20260808T142233", true))
	got := app.out.String()
	assert.Contains(t, got, "- local-secret")
	assert.Contains(t, got, "+ remote-secret")
}

func TestConflictsDiffOnAMissingEntry(t *testing.T) {
	app := newTestApp(t)
	err := app.runConflictsDiff("ghost.conflict-thinkpad-20260808T142233", false)
	assert.ErrorContains(t, err, "cannot read conflict files")
}

func TestConflictsResolveLocalRestoresTheOriginalName(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alice", "remote-secret\n")
	app.set(t, "alice.conflict-thinkpad-20260808T142233", "local-secret\n")

	require.NoError(t, app.runConflictsResolve("alice.conflict-thinkpad-20260808T142233", "local"))

	s, err := app.Store()
	require.NoError(t, err)
	// Keeping the local version means it is reachable under the name the
	// user actually types, not left behind as a conflict file.
	assert.False(t, s.Exists("alice.conflict-thinkpad-20260808T142233"))
	require.True(t, s.Exists("alice"))

	sec, err := s.Get("alice")
	require.NoError(t, err)
	assert.Equal(t, "local-secret", sec.Password())
}

func TestConflictsResolveRemoteRemovesTheConflictFile(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alice", "remote-secret\n")
	app.set(t, "alice.conflict-thinkpad-20260808T142233", "local-secret\n")

	require.NoError(t, app.runConflictsResolve("alice.conflict-thinkpad-20260808T142233", "remote"))

	s, err := app.Store()
	require.NoError(t, err)
	assert.True(t, s.Exists("alice"))
	assert.False(t, s.Exists("alice.conflict-thinkpad-20260808T142233"))
}

func TestConflictsResolveBothKeepsEverything(t *testing.T) {
	app := newTestApp(t)
	app.set(t, "alice", "remote-secret\n")
	app.set(t, "alice.conflict-thinkpad-20260808T142233", "local-secret\n")

	require.NoError(t, app.runConflictsResolve("alice.conflict-thinkpad-20260808T142233", "both"))

	s, err := app.Store()
	require.NoError(t, err)
	assert.True(t, s.Exists("alice"))
	assert.True(t, s.Exists("alice.conflict-thinkpad-20260808T142233"))
}

func TestConflictsResolveRejectsAnUnknownStrategy(t *testing.T) {
	app := newTestApp(t)
	err := app.runConflictsResolve("alice.conflict-thinkpad-20260808T142233", "yolo")
	assert.ErrorContains(t, err, `unknown strategy "yolo"`)
}

func TestConflictToOriginal(t *testing.T) {
	assert.Equal(t, "github.com/alice.gpg",
		conflictToOriginal("github.com/alice.conflict-thinkpad-20260808T142233.gpg"))
	assert.Equal(t, "alice.age",
		conflictToOriginal("alice.conflict-phone-20260808T142233.age"))
	assert.Equal(t, "alice.age", conflictToOriginal("alice.age"),
		"an ordinary entry is returned untouched")
}

func TestIsConflictFile(t *testing.T) {
	assert.True(t, isConflictFile("alice.conflict-phone-20260808T142233.age"))
	assert.False(t, isConflictFile("alice.age"))
}

func TestMaskLineHidesLength(t *testing.T) {
	assert.Equal(t, "*****", maskLine("abcde"))
	assert.Empty(t, maskLine(""))
}
