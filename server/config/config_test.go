package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("BINPASSD_PG_URL", "postgres://localhost/db")
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "8080", cfg.HTTP.Port)
	assert.Equal(t, "8081", cfg.GRPC.Port)
	assert.Equal(t, "fs", cfg.Blob.Driver)
	assert.Equal(t, 15*time.Minute, cfg.Auth.AccessTTL)
	assert.Equal(t, uint32(256), cfg.Auth.Argon2.MemoryMiB)
}

func TestLoadRequiresPGURL(t *testing.T) {
	t.Setenv("BINPASSD_PG_URL", "")
	_, err := Load("")
	assert.Error(t, err)
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("BINPASSD_PG_URL", "postgres://localhost/db")
	t.Setenv("BINPASSD_HTTP_PORT", "9999")
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "9999", cfg.HTTP.Port)
}

func TestSecretsFromEnvOnly(t *testing.T) {
	t.Setenv("BINPASSD_PG_URL", "postgres://localhost/db")
	t.Setenv("BINPASSD_JWT_PRIVATE_KEY", "seed-base64")
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, "seed-base64", cfg.Auth.JWTPrivateKey)
}
