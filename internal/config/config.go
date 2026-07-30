// Package config loads binpass client configuration from YAML, environment
// variables, and cobra flags, in that reverse order of precedence:
// flags > env > file > built-in defaults.
package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Config is the resolved client configuration.
type Config struct {
	// Store holds password-store location settings.
	Store StoreConfig `mapstructure:"store"`
	// Crypto holds identity/agent settings.
	Crypto CryptoConfig `mapstructure:"crypto"`
	// Clip holds clipboard settings.
	Clip ClipConfig `mapstructure:"clip"`
	// Generate holds default password-generation settings.
	Generate GenerateConfig `mapstructure:"generate"`
	// Log holds logging settings.
	Log LogConfig `mapstructure:"log"`
}

// StoreConfig configures the store location.
type StoreConfig struct {
	// Dir is the store root directory.
	Dir string `mapstructure:"dir"`
	// ObfuscateNames enables name obfuscation (not yet implemented).
	ObfuscateNames bool `mapstructure:"obfuscate_names"`
}

// CryptoConfig configures identities and the agent.
type CryptoConfig struct {
	// Identity is the path to the age identity file.
	Identity string `mapstructure:"identity"`
	// Agent configures the caching agent.
	Agent AgentConfig `mapstructure:"agent"`
}

// AgentConfig configures the identity-caching agent.
type AgentConfig struct {
	// Enabled turns the agent on.
	Enabled bool `mapstructure:"enabled"`
	// TTL is how long the agent caches an unlocked identity.
	TTL time.Duration `mapstructure:"ttl"`
}

// ClipConfig configures clipboard behaviour.
type ClipConfig struct {
	// Timeout is how long a secret stays on the clipboard.
	Timeout time.Duration `mapstructure:"timeout"`
	// RestorePrevious restores prior clipboard contents afterwards.
	RestorePrevious bool `mapstructure:"restore_previous"`
}

// GenerateConfig configures default password generation.
type GenerateConfig struct {
	// Length is the default generated password length.
	Length int `mapstructure:"length"`
	// Symbols includes symbols by default.
	Symbols bool `mapstructure:"symbols"`
}

// LogConfig configures logging.
type LogConfig struct {
	// Level is the slog level (debug|info|warn|error).
	Level string `mapstructure:"level"`
	// Format is text or json.
	Format string `mapstructure:"format"`
}

// Load resolves configuration by combining defaults, YAML, env, and flags.
func Load(cmd *cobra.Command) (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(userConfigDir())
	v.AddConfigPath(".")

	v.SetEnvPrefix("BINPASS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	setDefaults(v)

	// pass-compatibility aliases.
	_ = v.BindEnv("store.dir", "BINPASS_STORE_DIR", "PASSWORD_STORE_DIR")
	_ = v.BindEnv("clip.timeout", "BINPASS_CLIP_TIME", "PASSWORD_STORE_CLIP_TIME")
	_ = v.BindEnv("generate.length", "BINPASS_GENERATED_LENGTH", "PASSWORD_STORE_GENERATED_LENGTH")

	if cmd != nil {
		bindFlags(v, cmd)
		if cf, _ := cmd.Root().PersistentFlags().GetString("config"); cf != "" {
			v.SetConfigFile(cf)
		}
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	decode := viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		passDurationHook(),
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
	))
	if err := v.Unmarshal(&cfg, decode); err != nil {
		return nil, err
	}
	cfg.Store.Dir = expandHome(cfg.Store.Dir)
	cfg.Crypto.Identity = expandHome(cfg.Crypto.Identity)
	return &cfg, nil
}

// passDurationHook interprets a bare integer duration (as used by pass, e.g.
// PASSWORD_STORE_CLIP_TIME=45) as a number of seconds.
func passDurationHook() mapstructure.DecodeHookFuncType {
	return func(from, to reflect.Type, data any) (any, error) {
		if to != reflect.TypeOf(time.Duration(0)) {
			return data, nil
		}
		if from.Kind() != reflect.String {
			return data, nil
		}
		s := strings.TrimSpace(data.(string))
		if n, err := strconv.Atoi(s); err == nil {
			return time.Duration(n) * time.Second, nil
		}
		return data, nil
	}
}

// flagKeys maps persistent CLI flag names to their viper config keys. Flags
// are bound explicitly so that "--store" targets "store.dir" and does not
// shadow the store subtree.
var flagKeys = map[string]string{
	"store":     "store.dir",
	"log-level": "log.level",
}

// bindFlags binds recognised persistent flags to their viper keys, only when
// the flag was actually set (so unset flags never override env/file).
func bindFlags(v *viper.Viper, cmd *cobra.Command) {
	pf := cmd.Root().PersistentFlags()
	for flagName, key := range flagKeys {
		f := pf.Lookup(flagName)
		if f != nil && f.Changed {
			_ = v.BindPFlag(key, f)
		}
	}
}

// setDefaults populates built-in default values.
func setDefaults(v *viper.Viper) {
	home, _ := os.UserHomeDir()
	v.SetDefault("store.dir", filepath.Join(home, ".password-store"))
	v.SetDefault("store.obfuscate_names", false)
	v.SetDefault("crypto.identity", filepath.Join(userConfigDir(), "identities.age"))
	v.SetDefault("crypto.agent.enabled", true)
	v.SetDefault("crypto.agent.ttl", 10*time.Minute)
	v.SetDefault("clip.timeout", 45*time.Second)
	v.SetDefault("clip.restore_previous", true)
	v.SetDefault("generate.length", 24)
	v.SetDefault("generate.symbols", true)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "text")
}

// userConfigDir returns the binpass config directory.
func userConfigDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "binpass")
	}
	return filepath.Join(base, "binpass")
}

// ConfigDir exposes the binpass configuration directory.
func ConfigDir() string { return userConfigDir() }

// expandHome expands a leading ~ to the user's home directory.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
