package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// FilePath returns the path of the YAML config file.
func FilePath() string {
	if p := os.Getenv("BINPASS_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(configDir(), "binpass", "config.yaml")
}

// configDir returns the user's XDG config directory.
func configDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".config"
	}
	return filepath.Join(home, ".config")
}

// applyFile overlays the YAML config file onto cfg. A missing file is not an
// error: binpass is fully usable with no configuration at all.
func applyFile(cfg *Config) error {
	v := viper.New()
	v.SetConfigFile(FilePath())
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) || os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("config: %w", err)
	}

	if s := v.GetString("store.dir"); s != "" {
		cfg.Dir = expand(s)
	}
	if s := v.GetString("crypto.default"); s != "" {
		b := Backend(strings.ToLower(s))
		if b != BackendAge && b != BackendGPG {
			return fmt.Errorf("config: crypto.default must be age or gpg, got %q", s)
		}
		cfg.Default = b
	}
	if s := v.GetString("crypto.gpg.binary"); s != "" {
		cfg.GPGBinary = s
	}
	if s := v.GetStringSlice("crypto.gpg.opts"); len(s) > 0 {
		cfg.GPGOpts = s
	}
	if s := v.GetString("crypto.age.identity"); s != "" {
		cfg.Identity = expand(s)
	}
	if d := v.GetDuration("clip.timeout"); d > 0 {
		cfg.ClipTime = d
	}
	if n := v.GetInt("generate.length"); n > 0 {
		cfg.GeneratedLength = n
	}
	return nil
}
