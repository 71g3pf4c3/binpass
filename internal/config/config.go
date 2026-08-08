// Package config resolves binpass settings from flags, environment variables
// and the YAML config file, in that order of precedence.
//
// Every PASSWORD_STORE_* variable pass understands is honoured, and the
// matching BINPASS_* variable takes priority over it, so binpass can be
// dropped into an existing pass setup unchanged.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/pwgen"
)

// Backend names the crypto implementation used for new entries.
type Backend string

// Supported backends.
const (
	// BackendAge encrypts new entries with age.
	BackendAge Backend = "age"
	// BackendGPG encrypts new entries with GPG, as pass does.
	BackendGPG Backend = "gpg"
)

// Config is the resolved configuration of a binpass invocation.
type Config struct {
	// Dir is the password store root.
	Dir string
	// Default is the backend for new entries.
	Default Backend
	// Umask masks the permissions of created files.
	Umask os.FileMode
	// ClipTime is how long a copied password stays on the clipboard.
	ClipTime time.Duration
	// GeneratedLength is the default length of generated passwords.
	GeneratedLength int
	// CharacterSet is the alphabet for generated passwords.
	CharacterSet string
	// CharacterSetNoSymbols is the alphabet used with --no-symbols.
	CharacterSetNoSymbols string
	// SigningKey holds the GPG keys .gpg-id signatures are verified against.
	SigningKey string
	// GPGBinary overrides the gpg executable; empty means autodetect.
	GPGBinary string
	// GPGOpts are extra flags passed to every gpg invocation.
	GPGOpts []string
	// Identity is an explicit age identity file, from --identity.
	Identity string
	// XSelection is the X11 selection used for clipboard operations.
	XSelection string
}

// Default returns the configuration pass would use with no environment set.
func Default() Config {
	return Config{
		Dir:                   defaultDir(),
		Default:               BackendAge,
		Umask:                 0o077,
		ClipTime:              45 * time.Second,
		GeneratedLength:       pwgen.DefaultLength,
		CharacterSet:          pwgen.CharacterSet,
		CharacterSetNoSymbols: pwgen.CharacterSetNoSymbols,
		XSelection:            "clipboard",
	}
}

// Load resolves the configuration from the YAML file and the environment.
func Load() (Config, error) {
	cfg := Default()
	if err := applyFile(&cfg); err != nil {
		return cfg, err
	}
	applyEnv(&cfg)
	return cfg, nil
}

// applyEnv overlays environment variables onto cfg. For each setting the
// BINPASS_* form wins over the PASSWORD_STORE_* form.
func applyEnv(cfg *Config) {
	if v, ok := lookup("DIR"); ok {
		cfg.Dir = expand(v)
	}
	if v, ok := lookup("UMASK"); ok {
		if m, err := strconv.ParseUint(v, 8, 32); err == nil {
			cfg.Umask = os.FileMode(m)
		}
	}
	if v, ok := lookup("CLIP_TIME"); ok {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			cfg.ClipTime = time.Duration(secs) * time.Second
		}
	}
	if v, ok := lookup("GENERATED_LENGTH"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.GeneratedLength = n
		}
	}
	if v, ok := lookup("CHARACTER_SET"); ok {
		if set := pwgen.ExpandCharacterSet(v); set != "" {
			cfg.CharacterSet = set
		}
	}
	if v, ok := lookup("CHARACTER_SET_NO_SYMBOLS"); ok {
		if set := pwgen.ExpandCharacterSet(v); set != "" {
			cfg.CharacterSetNoSymbols = set
		}
	}
	if v, ok := lookup("SIGNING_KEY"); ok {
		cfg.SigningKey = v
	}
	if v, ok := lookup("GPG_OPTS"); ok {
		cfg.GPGOpts = strings.Fields(v)
	}
	if v, ok := lookup("X_SELECTION"); ok {
		cfg.XSelection = v
	}
	if v := os.Getenv("BINPASS_IDENTITY"); v != "" {
		cfg.Identity = expand(v)
	}
	if v := os.Getenv("BINPASS_GPG_BINARY"); v != "" {
		cfg.GPGBinary = v
	}
	if v := os.Getenv("BINPASS_DEFAULT_CRYPTO"); v != "" {
		if b := Backend(strings.ToLower(v)); b == BackendAge || b == BackendGPG {
			cfg.Default = b
		}
	}
}

// lookup reads a setting from BINPASS_<name>, falling back to
// PASSWORD_STORE_<name>.
func lookup(name string) (string, bool) {
	if v, ok := os.LookupEnv("BINPASS_" + name); ok {
		return v, true
	}
	return os.LookupEnv("PASSWORD_STORE_" + name)
}

// defaultDir returns ~/.password-store, the location pass uses.
func defaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".password-store"
	}
	return filepath.Join(home, ".password-store")
}

// expand resolves a leading ~ in a path.
func expand(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	return path
}
