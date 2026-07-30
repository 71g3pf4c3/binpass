package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PASSWORD_STORE_DIR", "")
	t.Setenv("BINPASS_STORE_DIR", "")
	t.Setenv("PASSWORD_STORE_CLIP_TIME", "")
	t.Setenv("PASSWORD_STORE_GENERATED_LENGTH", "")
	cfg, err := Load(nil)
	require.NoError(t, err)
	assert.Equal(t, 24, cfg.Generate.Length)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, 45*time.Second, cfg.Clip.Timeout)
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("PASSWORD_STORE_DIR", "")
	t.Setenv("BINPASS_STORE_DIR", "/tmp/custom-store")
	cfg, err := Load(nil)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/custom-store", cfg.Store.Dir)
}

func TestPassCompatDurationEnv(t *testing.T) {
	t.Setenv("PASSWORD_STORE_CLIP_TIME", "5")
	cfg, err := Load(nil)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, cfg.Clip.Timeout)
}

func TestPassCompatStoreDirEnv(t *testing.T) {
	t.Setenv("BINPASS_STORE_DIR", "")
	t.Setenv("PASSWORD_STORE_DIR", "/tmp/legacy")
	cfg, err := Load(nil)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/legacy", cfg.Store.Dir)
}
