package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/71g3pf4c3/binpass/server/config"
)

// TestFlagsOverrideEnv verifies flags take precedence over ENV and the config
// file when resolving the effective configuration.
func TestFlagsOverrideEnv(t *testing.T) {
	t.Setenv("BINPASSD_PG_URL", "postgres://localhost/db")
	t.Setenv("BINPASSD_HTTP_PORT", "9999")

	cmd := newRootCmd()
	require.NoError(t, cmd.Flags().Parse([]string{"--http-port", "7000", "--log-level", "debug"}))

	v := config.NewViper("")
	require.NoError(t, bindFlags(v, cmd.Flags()))

	cfg, err := config.LoadFromViper(v)
	require.NoError(t, err)
	assert.Equal(t, "7000", cfg.HTTP.Port, "flag should override ENV")
	assert.Equal(t, "debug", cfg.Log.Level)
}

// TestFlagKeysMatchFlagSet guards flagToKey against drifting from the declared
// flags.
func TestFlagKeysMatchFlagSet(t *testing.T) {
	cmd := newRootCmd()
	for name := range flagToKey {
		assert.NotNil(t, cmd.Flags().Lookup(name), "flag %q missing from command", name)
	}
}
