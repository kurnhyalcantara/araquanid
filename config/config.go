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
	Auth      Auth      `koanf:"auth"`
	Identity  Identity  `koanf:"identity"`
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

// Auth externalizes the Authentication Module parameters (FRD §16). All values
// are configurable; defaults() carries the FRD-recommended defaults.
type Auth struct {
	Lockout  Lockout  `koanf:"lockout"`
	Argon2id Argon2id `koanf:"argon2id"`
	Session  Session  `koanf:"session"`
	Token    Token    `koanf:"token"`
	MFA      MFA      `koanf:"mfa"`
	Device   Device   `koanf:"device"`
	FIDO2    FIDO2    `koanf:"fido2"`
}

// Lockout configures credential lockout (FRD §16.1).
type Lockout struct {
	Threshold     int           `koanf:"threshold"`
	Window        time.Duration `koanf:"window"`
	Tier1Duration time.Duration `koanf:"tier1_duration"`
	Tier2Duration time.Duration `koanf:"tier2_duration"`
}

// Argon2id configures the password hashing cost parameters (FRD §16.1).
type Argon2id struct {
	TimeCost    uint32 `koanf:"time_cost"`
	MemoryKB    uint32 `koanf:"memory_kb"`
	Parallelism uint8  `koanf:"parallelism"`
}

// Session configures session lifetimes and concurrency (FRD §16.2).
type Session struct {
	IdleTimeoutWeb    time.Duration `koanf:"idle_timeout_web"`
	IdleTimeoutMobile time.Duration `koanf:"idle_timeout_mobile"`
	AbsoluteWeb       time.Duration `koanf:"absolute_web"`
	AbsoluteMobile    time.Duration `koanf:"absolute_mobile"`
	ConcurrentPolicy  string        `koanf:"concurrent_policy"`
	ConcurrentMax     int           `koanf:"concurrent_max"`
	MFASessionWindow  time.Duration `koanf:"mfa_session_window"`
}

// Token configures access/refresh token lifetimes and issuance (FRD §16.3).
type Token struct {
	AccessTTL           time.Duration `koanf:"access_ttl"`
	RefreshTTLWeb       time.Duration `koanf:"refresh_ttl_web"`
	RefreshTTLMobile    time.Duration `koanf:"refresh_ttl_mobile"`
	Issuer              string        `koanf:"issuer"`
	RotationGraceWindow time.Duration `koanf:"rotation_grace_window"`
}

// MFA configures OTP/TOTP/recovery-code behavior (FRD §16.5).
type MFA struct {
	OTPTTL                   time.Duration `koanf:"otp_ttl"`
	OTPMaxAttempts           int           `koanf:"otp_max_attempts"`
	OTPResendRateLimit       int           `koanf:"otp_resend_rate_limit"`
	OTPResendWindow          time.Duration `koanf:"otp_resend_window"`
	TOTPWindow               int           `koanf:"totp_window"`
	EnrollmentWindow         time.Duration `koanf:"enrollment_window"`
	RecoveryCodeCount        int           `koanf:"recovery_code_count"`
	RecoveryCodeLowThreshold int           `koanf:"recovery_code_low_threshold"`
}

// Device configures device fingerprinting and trust (FRD §16.6).
type Device struct {
	TrustDuration      time.Duration `koanf:"trust_duration"`
	FingerprintVersion int           `koanf:"fingerprint_version"`
}

// FIDO2 configures the WebAuthn relying party (FRD §16.7).
type FIDO2 struct {
	RPID             string        `koanf:"rp_id"`
	RPName           string        `koanf:"rp_name"`
	RPOrigin         string        `koanf:"rp_origin"`
	UserVerification string        `koanf:"user_verification"`
	Attestation      string        `koanf:"attestation"`
	ChallengeTTL     time.Duration `koanf:"challenge_ttl"`
}

// Identity configures the Identity Context anti-corruption client the auth
// module dials to resolve identifiers and read display data.
type Identity struct {
	// Addr is the Identity Context gRPC endpoint (host:port). Empty leaves the
	// ACL client unconfigured; calls then fail as unavailable.
	Addr string `koanf:"addr"`
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

		// Authentication Module (FRD §16). Durations use Go duration syntax.
		"auth.lockout.threshold":               5,
		"auth.lockout.window":                  "15m",
		"auth.lockout.tier1_duration":          "30m",
		"auth.lockout.tier2_duration":          "2h",
		"auth.argon2id.time_cost":              3,
		"auth.argon2id.memory_kb":              65536,
		"auth.argon2id.parallelism":            4,
		"auth.session.idle_timeout_web":        "15m",
		"auth.session.idle_timeout_mobile":     "30m",
		"auth.session.absolute_web":            "8h",
		"auth.session.absolute_mobile":         "24h",
		"auth.session.concurrent_policy":       "LIMIT_N",
		"auth.session.concurrent_max":          5,
		"auth.session.mfa_session_window":      "10m",
		"auth.token.access_ttl":                "15m",
		"auth.token.refresh_ttl_web":           "24h",
		"auth.token.refresh_ttl_mobile":        "168h",
		"auth.token.issuer":                    "https://auth.bank.com",
		"auth.token.rotation_grace_window":     "5s",
		"auth.mfa.otp_ttl":                     "5m",
		"auth.mfa.otp_max_attempts":            3,
		"auth.mfa.otp_resend_rate_limit":       3,
		"auth.mfa.otp_resend_window":           "10m",
		"auth.mfa.totp_window":                 1,
		"auth.mfa.enrollment_window":           "5m",
		"auth.mfa.recovery_code_count":         10,
		"auth.mfa.recovery_code_low_threshold": 3,
		"auth.device.trust_duration":           "720h",
		"auth.device.fingerprint_version":      1,
		"auth.fido2.rp_id":                     "bank.com",
		"auth.fido2.rp_name":                   "Corporate Bank",
		"auth.fido2.rp_origin":                 "https://portal.bank.com",
		"auth.fido2.user_verification":         "preferred",
		"auth.fido2.attestation":               "indirect",
		"auth.fido2.challenge_ttl":             "5m",
		"identity.addr":                        "",
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
