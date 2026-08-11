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

// DataDir returns $XDG_DATA_HOME/binpass, the sidecar directory for state
// that must never end up inside the store: plugins, their grants, and caches.
func DataDir() string {
	if d := os.Getenv("BINPASS_DATA_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "binpass")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "binpass")
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
	if s := v.GetString("sync.auto"); s != "" {
		cfg.Sync.Auto = s
	}
	if s := v.GetString("sync.conflict"); s != "" {
		cfg.Sync.Conflict = s
	}
	if s := v.GetString("sync.default_remote"); s != "" {
		cfg.Sync.DefaultRemote = s
	}

	// Remotes: sync.remotes.<name>.type, .url, .folder, .sign_commits.
	remotesKey := "sync.remotes"
	if v.IsSet(remotesKey) {
		remotes := v.GetStringMap(remotesKey)
		if cfg.Remotes == nil {
			cfg.Remotes = make(map[string]RemoteConfig, len(remotes))
		}
		for name := range remotes {
			prefix := remotesKey + "." + name + "."
			rc := RemoteConfig{
				Type:            v.GetString(prefix + "type"),
				URL:             v.GetString(prefix + "url"),
				Folder:          v.GetString(prefix + "folder"),
				SignCommits:     v.GetBool(prefix + "sign_commits"),
				Password:        v.GetString(prefix + "password"),
				PasswordCommand: v.GetString(prefix + "password_command"),
			}
			if rc.Type != "" {
				cfg.Remotes[name] = rc
			}
		}
	}
	return nil
}
