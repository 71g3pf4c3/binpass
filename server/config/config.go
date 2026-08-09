// Package config loads binpassd configuration from a YAML file, environment
// variables, and validates it. Secrets (PG URL, JWT key) come only from ENV;
// the YAML file holds non-sensitive defaults.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// Config is the resolved server configuration.
type Config struct {
	// App holds application metadata.
	App App `mapstructure:"app"`
	// HTTP configures the REST/gateway server.
	HTTP HTTP `mapstructure:"http"`
	// GRPC configures the gRPC server.
	GRPC GRPC `mapstructure:"grpc"`
	// PG configures PostgreSQL.
	PG PG `mapstructure:"pg"`
	// Blob configures the blob store.
	Blob Blob `mapstructure:"blob"`
	// Auth configures authentication.
	Auth Auth `mapstructure:"auth"`
	// Limits configures quotas and rate limits.
	Limits Limits `mapstructure:"limits"`
	// Log configures logging.
	Log Log `mapstructure:"log"`
}

// App holds application metadata.
type App struct {
	// Name is the application name.
	Name string `mapstructure:"name"`
	// Version is set at build time via ldflags.
	Version string `mapstructure:"version"`
}

// HTTP configures the REST/gateway server.
type HTTP struct {
	// Port is the HTTP listen port.
	Port string `mapstructure:"port" validate:"required"`
	// ReadTimeout bounds request reads.
	ReadTimeout time.Duration `mapstructure:"read_timeout"`
	// WriteTimeout bounds response writes.
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

// GRPC configures the gRPC server.
type GRPC struct {
	// Port is the gRPC listen port.
	Port string `mapstructure:"port" validate:"required"`
	// MaxRecvMiB is the max receive message size in mebibytes.
	MaxRecvMiB int `mapstructure:"max_recv_mib"`
	// Keepalive is the server keepalive interval.
	Keepalive time.Duration `mapstructure:"keepalive"`
}

// PG configures PostgreSQL.
type PG struct {
	// PoolMax is the max connection pool size.
	PoolMax int32 `mapstructure:"pool_max"`
	// URL is the connection string; ENV only (BINPASSD_PG_URL).
	URL string `mapstructure:"url" validate:"required"`
}

// Blob configures the blob store.
type Blob struct {
	// Driver is "fs" or "s3".
	Driver string `mapstructure:"driver" validate:"required,oneof=fs s3"`
	// FSPath is the blob directory for the fs driver.
	FSPath string `mapstructure:"fs_path"`
}

// Auth configures authentication.
type Auth struct {
	// Argon2 holds Argon2id cost parameters.
	Argon2 Argon2 `mapstructure:"argon2"`
	// AccessTTL is the access-token lifetime.
	AccessTTL time.Duration `mapstructure:"access_ttl"`
	// RefreshTTL is the refresh-token lifetime.
	RefreshTTL time.Duration `mapstructure:"refresh_ttl"`
	// JWTPrivateKey is the base64 Ed25519 seed; ENV only.
	JWTPrivateKey string `mapstructure:"jwt_private_key"`
}

// Argon2 holds Argon2id cost parameters.
type Argon2 struct {
	// MemoryMiB is the memory cost in mebibytes.
	MemoryMiB uint32 `mapstructure:"memory_mib"`
	// Time is the iteration count.
	Time uint32 `mapstructure:"time"`
	// Threads is the parallelism.
	Threads uint8 `mapstructure:"threads"`
}

// Limits configures quotas and rate limits.
type Limits struct {
	// MaxObjectSize is the max single-object byte length.
	MaxObjectSize int64 `mapstructure:"max_object_size"`
	// QuotaPerUser is the per-user byte quota.
	QuotaPerUser int64 `mapstructure:"quota_per_user"`
	// RateLoginPerMin is the per-identity login rate limit.
	RateLoginPerMin int `mapstructure:"rate_login_per_min"`
}

// Log configures logging.
type Log struct {
	// Level is the slog level.
	Level string `mapstructure:"level"`
	// Format is json or text.
	Format string `mapstructure:"format"`
}

// NewViper builds a viper instance wired with binpassd defaults, the ENV
// overlay (prefix BINPASSD), and ENV-only secret bindings. It does not read the
// config file yet, so callers may bind command-line flags before calling Load.
func NewViper(path string) *viper.Viper {
	v := viper.New()
	v.SetConfigType("yaml")
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath("./config")
		v.AddConfigPath(".")
	}

	v.SetEnvPrefix("BINPASSD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	setDefaults(v)

	// Secrets from ENV only.
	_ = v.BindEnv("pg.url", "BINPASSD_PG_URL")
	_ = v.BindEnv("auth.jwt_private_key", "BINPASSD_JWT_PRIVATE_KEY")

	return v
}

// LoadFromViper reads the config file (if present), unmarshals, and validates
// the config from an already-configured viper instance. Precedence is
// flags > ENV > config file > defaults.
func LoadFromViper(v *viper.Viper) (*Config, error) {
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	if err := validator.New().Struct(&cfg); err != nil {
		return nil, fmt.Errorf("config: validation: %w", err)
	}
	return &cfg, nil
}

// Load reads config from path (optional), overlays ENV (prefix BINPASSD), and
// validates the result.
func Load(path string) (*Config, error) {
	return LoadFromViper(NewViper(path))
}

// setDefaults populates non-secret defaults.
func setDefaults(v *viper.Viper) {
	v.SetDefault("app.name", "binpassd")
	v.SetDefault("http.port", "8080")
	v.SetDefault("http.read_timeout", 10*time.Second)
	v.SetDefault("http.write_timeout", 30*time.Second)
	v.SetDefault("http.shutdown_timeout", 15*time.Second)
	v.SetDefault("grpc.port", "8081")
	v.SetDefault("grpc.max_recv_mib", 8)
	v.SetDefault("grpc.keepalive", 30*time.Second)
	v.SetDefault("pg.pool_max", 20)
	v.SetDefault("blob.driver", "fs")
	v.SetDefault("blob.fs_path", "/var/lib/binpassd/blobs")
	v.SetDefault("auth.argon2.memory_mib", 256)
	v.SetDefault("auth.argon2.time", 3)
	v.SetDefault("auth.argon2.threads", 4)
	v.SetDefault("auth.access_ttl", 15*time.Minute)
	v.SetDefault("auth.refresh_ttl", 720*time.Hour)
	v.SetDefault("limits.max_object_size", 100*1024*1024)
	v.SetDefault("limits.quota_per_user", int64(5)*1024*1024*1024)
	v.SetDefault("limits.rate_login_per_min", 10)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
}
