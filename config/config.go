// Package config loads application configuration with the precedence:
// defaults < environment variables. Environment variables (ARAQUANID_ prefix,
// "__" separates nesting levels, e.g. ARAQUANID_POSTGRES__MAX_CONNS overrides
// postgres.max_conns) are the source of truth; see .env.example. A yaml file
// is also supported via --config for local stacking, but is optional and
// loaded before env so env still wins.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const envPrefix = "ARAQUANID_"

type Config struct {
	App       App       `koanf:"app"`
	Server    Server    `koanf:"server"`
	Postgres  Postgres  `koanf:"postgres"`
	Redis     Redis     `koanf:"redis"`
	Log       Log       `koanf:"log"`
	Telemetry Telemetry `koanf:"telemetry"`
}

type App struct {
	Name    string `koanf:"name"`
	Env     string `koanf:"env"` // development | staging | production
	Version string `koanf:"version"`
}

func (a App) IsProduction() bool { return a.Env == "production" }

type Server struct {
	GRPCPort        int           `koanf:"grpc_port"`
	HTTPPort        int           `koanf:"http_port"`
	MetricsPort     int           `koanf:"metrics_port"`
	ShutdownTimeout time.Duration `koanf:"shutdown_timeout"`
}

type Postgres struct {
	Host            string        `koanf:"host"`
	Port            int           `koanf:"port"`
	User            string        `koanf:"user"`
	Password        string        `koanf:"password"`
	Database        string        `koanf:"database"`
	SSLMode         string        `koanf:"ssl_mode"`
	MaxConns        int32         `koanf:"max_conns"`
	MinConns        int32         `koanf:"min_conns"`
	MaxConnLifetime time.Duration `koanf:"max_conn_lifetime"`
}

func (p Postgres) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password, p.Host, p.Port, p.Database, p.SSLMode)
}

type Redis struct {
	Addr     string `koanf:"addr"`
	Password string `koanf:"password"`
	DB       int    `koanf:"db"`
	// CacheTTL bounds how long the read-through cache decorator keeps entries.
	CacheTTL time.Duration `koanf:"cache_ttl"`
}

type Log struct {
	Level  string `koanf:"level"`  // debug | info | warn | error
	Format string `koanf:"format"` // json | text
}

type Telemetry struct {
	Enabled      bool    `koanf:"enabled"`
	OTLPEndpoint string  `koanf:"otlp_endpoint"`
	SampleRatio  float64 `koanf:"sample_ratio"`
}

func defaults() map[string]any {
	return map[string]any{
		"app.name":                   "araquanid",
		"app.env":                    "development",
		"app.version":                "dev",
		"server.grpc_port":           9090,
		"server.http_port":           8080,
		"server.metrics_port":        9100,
		"server.shutdown_timeout":    "15s",
		"postgres.host":              "localhost",
		"postgres.port":              5432,
		"postgres.user":              "araquanid",
		"postgres.database":          "araquanid",
		"postgres.ssl_mode":          "disable",
		"postgres.max_conns":         10,
		"postgres.min_conns":         2,
		"postgres.max_conn_lifetime": "1h",
		"redis.addr":                 "localhost:6379",
		"redis.db":                   0,
		"redis.cache_ttl":            "5m",
		"log.level":                  "info",
		"log.format":                 "json",
		"telemetry.enabled":          false,
		"telemetry.otlp_endpoint":    "localhost:4317",
		"telemetry.sample_ratio":     1.0,
	}
}

// Load reads configuration from the given yaml path (optional) and the
// environment, applies defaults, and validates the result.
func Load(path string) (*Config, error) {
	k := koanf.New(".")

	if err := k.Load(confmap.Provider(defaults(), "."), nil); err != nil {
		return nil, fmt.Errorf("config: load defaults: %w", err)
	}

	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("config: load %s: %w", path, err)
		}
	}

	envProvider := env.Provider(envPrefix, ".", func(s string) string {
		key := strings.ToLower(strings.TrimPrefix(s, envPrefix))
		return strings.ReplaceAll(key, "__", ".")
	})
	if err := k.Load(envProvider, nil); err != nil {
		return nil, fmt.Errorf("config: load env: %w", err)
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Postgres.Host == "" {
		return fmt.Errorf("config: postgres.host is required (set ARAQUANID_POSTGRES__HOST)")
	}
	return nil
}
