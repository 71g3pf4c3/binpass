package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/pwgen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolate points the loader at an empty config directory and clears every
// setting the developer's own shell may export, so that a test measures the
// loader rather than the machine it runs on.
func isolate(t *testing.T) string {
	t.Helper()
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(key, "PASSWORD_STORE_") || strings.HasPrefix(key, "BINPASS_") {
			unset(t, key)
		}
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("BINPASS_CONFIG", filepath.Join(dir, "binpass", "config.yaml"))
	return dir
}

// unset removes an environment variable for the duration of a test.
func unset(t *testing.T, key string) {
	t.Helper()
	old, ok := os.LookupEnv(key)
	require.NoError(t, os.Unsetenv(key))
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(key, old)
		}
	})
}

func TestDefaults(t *testing.T) {
	isolate(t)
	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, config.BackendAge, cfg.Default)
	assert.Equal(t, os.FileMode(0o077), cfg.Umask)
	assert.Equal(t, 45*time.Second, cfg.ClipTime)
	assert.Equal(t, pwgen.DefaultLength, cfg.GeneratedLength)
	assert.Equal(t, pwgen.CharacterSet, cfg.CharacterSet)
	assert.Contains(t, cfg.Dir, ".password-store")
}

func TestPasswordStoreEnvIsHonoured(t *testing.T) {
	isolate(t)
	t.Setenv("PASSWORD_STORE_DIR", "/srv/store")
	t.Setenv("PASSWORD_STORE_CLIP_TIME", "10")
	t.Setenv("PASSWORD_STORE_GENERATED_LENGTH", "42")
	t.Setenv("PASSWORD_STORE_UMASK", "027")
	t.Setenv("PASSWORD_STORE_CHARACTER_SET", "[:digit:]")
	t.Setenv("PASSWORD_STORE_SIGNING_KEY", "ABCD1234")
	t.Setenv("PASSWORD_STORE_GPG_OPTS", "--no-throw-keyids --armor")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "/srv/store", cfg.Dir)
	assert.Equal(t, 10*time.Second, cfg.ClipTime)
	assert.Equal(t, 42, cfg.GeneratedLength)
	assert.Equal(t, os.FileMode(0o027), cfg.Umask)
	assert.Equal(t, "0123456789", cfg.CharacterSet)
	assert.Equal(t, "ABCD1234", cfg.SigningKey)
	assert.Equal(t, []string{"--no-throw-keyids", "--armor"}, cfg.GPGOpts)
}

func TestBinpassEnvBeatsPasswordStoreEnv(t *testing.T) {
	isolate(t)
	t.Setenv("PASSWORD_STORE_DIR", "/from/pass")
	t.Setenv("BINPASS_DIR", "/from/binpass")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "/from/binpass", cfg.Dir)
}

func TestEnvBeatsFile(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, "store:\n  dir: /from/file\n")
	t.Setenv("PASSWORD_STORE_DIR", "/from/env")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "/from/env", cfg.Dir)
}

func TestFileSettings(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, `
store:
  dir: /from/file
crypto:
  default: gpg
  gpg:
    binary: gpg2
    opts: ["--armor"]
clip:
  timeout: 90s
generate:
  length: 64
`)
	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "/from/file", cfg.Dir)
	assert.Equal(t, config.BackendGPG, cfg.Default)
	assert.Equal(t, "gpg2", cfg.GPGBinary)
	assert.Equal(t, []string{"--armor"}, cfg.GPGOpts)
	assert.Equal(t, 90*time.Second, cfg.ClipTime)
	assert.Equal(t, 64, cfg.GeneratedLength)
}

func TestInvalidBackendInFileIsAnError(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, "crypto:\n  default: rot13\n")

	_, err := config.Load()
	assert.Error(t, err)
}

func TestMalformedFileIsAnError(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, "store: [this is not: a mapping\n")

	_, err := config.Load()
	assert.Error(t, err, "a broken config must be reported, not silently ignored")
}

func TestMissingFileIsFine(t *testing.T) {
	isolate(t)
	_, err := config.Load()
	assert.NoError(t, err)
}

func TestInvalidEnvValuesFallBackToDefaults(t *testing.T) {
	isolate(t)
	t.Setenv("PASSWORD_STORE_CLIP_TIME", "soon")
	t.Setenv("PASSWORD_STORE_GENERATED_LENGTH", "-5")
	t.Setenv("PASSWORD_STORE_UMASK", "not-octal")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 45*time.Second, cfg.ClipTime)
	assert.Equal(t, pwgen.DefaultLength, cfg.GeneratedLength)
	assert.Equal(t, os.FileMode(0o077), cfg.Umask)
}

func TestTildeIsExpanded(t *testing.T) {
	isolate(t)
	t.Setenv("PASSWORD_STORE_DIR", "~/store")

	cfg, err := config.Load()
	require.NoError(t, err)

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, "store"), cfg.Dir)
}

// writeConfig places a config file where the loader will find it.
func writeConfig(t *testing.T, dir, body string) {
	t.Helper()
	path := filepath.Join(dir, "binpass", "config.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}
