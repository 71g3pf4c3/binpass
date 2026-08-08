package plugin_test

import (
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseManifest(t *testing.T) {
	m, err := plugin.ParseManifest([]byte(`
name: rotate
version: 1.2.0
api: 1
description: Rotate credentials
capabilities:
  read_paths: ["work/**"]
  write_paths: ["work/**"]
  decrypt: true
  network: ["api.example.com"]
`))
	require.NoError(t, err)

	assert.Equal(t, "rotate", m.Name)
	assert.Equal(t, plugin.LevelExec, m.Level, "level defaults to a plain executable")
	assert.Equal(t, "binpass-rotate", m.Binary())
	assert.True(t, m.Capabilities.Decrypt)
	assert.True(t, m.Sensitive())
}

func TestParseManifestRejects(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "no name",
			yaml:    "api: 1\n",
			wantErr: "name is required",
		},
		{
			name:    "name that could shadow a path",
			yaml:    "name: ../evil\napi: 1\n",
			wantErr: "must be lowercase",
		},
		{
			name:    "no api version",
			yaml:    "name: x\n",
			wantErr: "api is required",
		},
		{
			name:    "api version from the future",
			yaml:    "name: x\napi: 99\n",
			wantErr: "needs api 99",
		},
		{
			name:    "impossible level",
			yaml:    "name: x\napi: 1\nlevel: 7\n",
			wantErr: "not one of",
		},
		{
			// A manifest asking to decrypt nothing is not dangerous, but it
			// is evidence its author meant something else.
			name:    "decrypt without any readable path",
			yaml:    "name: x\napi: 1\ncapabilities:\n  decrypt: true\n",
			wantErr: "could decrypt nothing",
		},
		{
			name:    "network entry given as a URL",
			yaml:    "name: x\napi: 1\ncapabilities:\n  network: [\"https://a.example/path\"]\n",
			wantErr: "must be a host",
		},
		{
			// The important one: a mistyped capability key must not be
			// silently dropped, or the plugin would appear to request less
			// than its author wrote.
			name:    "misspelled capability key",
			yaml:    "name: x\napi: 1\ncapabilities:\n  read_path: [\"**\"]\n",
			wantErr: "field read_path not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := plugin.ParseManifest([]byte(tt.yaml))
			require.Error(t, err)
			assert.ErrorIs(t, err, plugin.ErrInvalidManifest)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestManifestBinaryOverride(t *testing.T) {
	m, err := plugin.ParseManifest([]byte("name: x\napi: 1\nexec: helper.py\n"))
	require.NoError(t, err)
	assert.Equal(t, "helper.py", m.Binary())
}

// TestSummaryLeadsWithTheConsequence checks that approval text describes what
// access means, not which YAML keys were set. Someone deciding whether to
// trust a plugin needs to be told it will see their passwords.
func TestSummaryLeadsWithTheConsequence(t *testing.T) {
	m, err := plugin.ParseManifest([]byte(`
name: x
api: 1
capabilities:
  read_paths: ["**"]
  decrypt: true
`))
	require.NoError(t, err)

	s := m.Summary()
	assert.Contains(t, s, "CAN READ YOUR PASSWORDS IN PLAINTEXT")
	assert.Contains(t, s, "writes:  nothing")
	assert.Contains(t, s, "network: none")
}

func TestSummaryOfAHarmlessPlugin(t *testing.T) {
	m, err := plugin.ParseManifest([]byte("name: x\napi: 1\n"))
	require.NoError(t, err)

	assert.False(t, m.Sensitive())
	assert.Contains(t, m.Summary(), "reads:   nothing")
}
