// Package config loads application configuration with the precedence:
// yaml file < environment variables. The yaml file (config/config.yaml by
// default, see --config) is read first and carries every default value; there
// are no in-code defaults. Environment variables (ARAQUANID_ prefix, "__"
// separates nesting levels, e.g. ARAQUANID_POSTGRES__MAX_CONNS overrides
// postgres.max_conns) are layered on top, so env still wins; see .env.example.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const envPrefix = "ARAQUANID_"

type (
	Config struct {
		App       App       `koanf:"app"`
		OpsServer OpsServer `koanf:"ops_server"`
		Postgres  Postgres  `koanf:"postgres"`
		Redis     Redis     `koanf:"redis"`
		Log       Log       `koanf:"log"`
		Telemetry Telemetry `koanf:"telemetry"`
		Services  Services  `koanf:"services"`
		Auth      Auth      `koanf:"auth"`
		Kafka     Kafka     `koanf:"kafka"`
	}

	App struct {
		Name    string `koanf:"name"`
		Env     string `koanf:"env"` // development | staging | production
		Version string `koanf:"version"`
	}

	OpsServer struct {
		MetricsPort     int           `koanf:"metrics_port"`
		ShutdownTimeout time.Duration `koanf:"shutdown_timeout"`
	}

	Postgres struct {
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

	Redis struct {
		Addr       string        `koanf:"addr"`
		Password   string        `koanf:"password"`
		DB         int           `koanf:"db"`
		DefaultTTL time.Duration `koanf:"default_ttl"`
	}

	Log struct {
		Level  string `koanf:"level"`  // debug | info | warn | error
		Format string `koanf:"format"` // json | text
	}

	Telemetry struct {
		Enabled      bool    `koanf:"enabled"`
		OTLPEndpoint string  `koanf:"otlp_endpoint"`
		SampleRatio  float64 `koanf:"sample_ratio"`
	}

	Services struct {
		Identity Identity `koanf:"identity"`
	}

	Identity struct {
		Addr string `koanf:"addr"`
	}

	Kafka struct {
		Brokers         []string      `koanf:"brokers"`
		OutboxTopic     string        `koanf:"outbox_topic"`
		PublishInterval time.Duration `koanf:"publish_interval"`
		BatchSize       int           `koanf:"batch_size"`
	}

	Auth struct {
		Session   Session   `koanf:"session"`
		Token     Token     `koanf:"token"`
		RateLimit RateLimit `koanf:"rate_limit"`
		Lockout   Lockout   `koanf:"lockout"`
		Argon2id  Argon2id  `koanf:"argon2id"`
		MFA       MFA       `koanf:"mfa"`
		Device    Device    `koanf:"device"`
		FIDO2     FIDO2     `koanf:"fido2"`
	}

	// Session configures session lifetimes and concurrency.
	Session struct {
		IdleTimeoutWeb     time.Duration `koanf:"idle_timeout_web"`
		IdleTimeoutMobile  time.Duration `koanf:"idle_timeout_mobile"`
		AbsoluteWeb        time.Duration `koanf:"absolute_web"`
		AbsoluteMobile     time.Duration `koanf:"absolute_mobile"`
		ConcurrentPolicy   string        `koanf:"concurrent_policy"`
		ConcurrentMax      int           `koanf:"concurrent_max"`
		MFASessionWindow   time.Duration `koanf:"mfa_session_window"`
		ForcedChangeWindow time.Duration `koanf:"forced_change_window"`
	}

	// Token configures access/refresh token lifetimes and issuance.
	Token struct {
		AccessTTL           time.Duration `koanf:"access_ttl"`
		RefreshTTLWeb       time.Duration `koanf:"refresh_ttl_web"`
		RefreshTTLMobile    time.Duration `koanf:"refresh_ttl_mobile"`
		Issuer              string        `koanf:"issuer"`
		RotationGraceWindow time.Duration `koanf:"rotation_grace_window"`
		PrivateKeyPEM       string        `koanf:"private_key_pem"`
		PrivateKeyPath      string        `koanf:"private_key_path"`
		Kid                 string        `koanf:"kid"`
	}

	// Lockout configures the account lockout policy.
	Lockout struct {
		Threshold     int           `koanf:"threshold"`
		Window        time.Duration `koanf:"window"`
		Tier1Duration time.Duration `koanf:"tier1_duration"`
		Tier2Duration time.Duration `koanf:"tier2_duration"`
	}

	// Argon2id configures the password hashing cost parameters.
	Argon2id struct {
		TimeCost    uint32 `koanf:"time_cost"`
		MemoryKB    uint32 `koanf:"memory_kb"`
		Parallelism uint8  `koanf:"parallelism"`
	}

	// RateLimit configures the login rate limiter.
	RateLimit struct {
		IPMaxAttempts       int           `koanf:"ip_max_attempts"`
		IPWindow            time.Duration `koanf:"ip_window"`
		IdentityMaxAttempts int           `koanf:"identity_max_attempts"`
		IdentityWindow      time.Duration `koanf:"identity_window"`
	}

	// MFA configures OTP/TOTP/recovery-code behavior.
	MFA struct {
		OTPTTL                   time.Duration `koanf:"otp_ttl"`
		OTPMaxAttempts           int           `koanf:"otp_max_attempts"`
		OTPResendRateLimit       int           `koanf:"otp_resend_rate_limit"`
		OTPResendWindow          time.Duration `koanf:"otp_resend_window"`
		TOTPWindow               int           `koanf:"totp_window"`
		EnrollmentWindow         time.Duration `koanf:"enrollment_window"`
		RecoveryCodeCount        int           `koanf:"recovery_code_count"`
		RecoveryCodeLowThreshold int           `koanf:"recovery_code_low_threshold"`
	}

	// Device configures device fingerprinting and trust.
	Device struct {
		TrustDuration      time.Duration `koanf:"trust_duration"`
		FingerprintVersion int           `koanf:"fingerprint_version"`
	}

	// FIDO2 configures the WebAuthn relying party.
	FIDO2 struct {
		RPID             string        `koanf:"rp_id"`
		RPName           string        `koanf:"rp_name"`
		RPOrigin         string        `koanf:"rp_origin"`
		UserVerification string        `koanf:"user_verification"`
		Attestation      string        `koanf:"attestation"`
		ChallengeTTL     time.Duration `koanf:"challenge_ttl"`
	}
)

func (a App) IsProduction() bool { return a.Env == "production" }

func (p Postgres) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password, p.Host, p.Port, p.Database, p.SSLMode)
}

// Load reads configuration from the YAML file at the given path.
// Environment variables (prefixed with envPrefix) override matching
// values from the file when present.
func Load(path string) (*Config, error) {
	k := koanf.New(".")

	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("config: load %s: %w", path, err)
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

// validate reports every required key that is unset.
func (c *Config) validate() error {
	var missing []string
	req := func(key string, ok bool) {
		if !ok {
			missing = append(missing, key)
		}
	}

	req("app.name", c.App.Name != "")
	req("app.env", c.App.Env != "")
	req("ops_server.metrics_port", c.OpsServer.MetricsPort > 0)
	req("ops_server.shutdown_timeout", c.OpsServer.ShutdownTimeout > 0)

	req("postgres.host", c.Postgres.Host != "")
	req("postgres.port", c.Postgres.Port > 0)
	req("postgres.user", c.Postgres.User != "")
	req("postgres.database", c.Postgres.Database != "")
	req("postgres.ssl_mode", c.Postgres.SSLMode != "")
	req("postgres.max_conns", c.Postgres.MaxConns > 0)
	req("postgres.max_conn_lifetime", c.Postgres.MaxConnLifetime > 0)

	req("redis.addr", c.Redis.Addr != "")
	req("redis.default_ttl", c.Redis.DefaultTTL > 0)
	req("log.level", c.Log.Level != "")
	req("log.format", c.Log.Format != "")
	req("telemetry.otlp_endpoint", !c.Telemetry.Enabled || c.Telemetry.OTLPEndpoint != "")

	a := c.Auth
	req("auth.lockout.threshold", a.Lockout.Threshold > 0)
	req("auth.lockout.window", a.Lockout.Window > 0)
	req("auth.lockout.tier1_duration", a.Lockout.Tier1Duration > 0)
	req("auth.lockout.tier2_duration", a.Lockout.Tier2Duration > 0)
	req("auth.argon2id.time_cost", a.Argon2id.TimeCost > 0)
	req("auth.argon2id.memory_kb", a.Argon2id.MemoryKB > 0)
	req("auth.argon2id.parallelism", a.Argon2id.Parallelism > 0)
	req("auth.session.idle_timeout_web", a.Session.IdleTimeoutWeb > 0)
	req("auth.session.idle_timeout_mobile", a.Session.IdleTimeoutMobile > 0)
	req("auth.session.absolute_web", a.Session.AbsoluteWeb > 0)
	req("auth.session.absolute_mobile", a.Session.AbsoluteMobile > 0)
	req("auth.session.concurrent_policy", a.Session.ConcurrentPolicy != "")
	req("auth.session.concurrent_max", a.Session.ConcurrentMax > 0)
	req("auth.session.mfa_session_window", a.Session.MFASessionWindow > 0)
	req("auth.session.forced_change_window", a.Session.ForcedChangeWindow > 0)
	req("auth.token.access_ttl", a.Token.AccessTTL > 0)
	req("auth.token.refresh_ttl_web", a.Token.RefreshTTLWeb > 0)
	req("auth.token.refresh_ttl_mobile", a.Token.RefreshTTLMobile > 0)
	req("auth.token.issuer", a.Token.Issuer != "")
	req("auth.token.kid", a.Token.Kid != "")
	req("auth.token.private_key_pem or auth.token.private_key_path",
		a.Token.PrivateKeyPEM != "" || a.Token.PrivateKeyPath != "")
	req("auth.rate_limit.ip_max_attempts", a.RateLimit.IPMaxAttempts > 0)
	req("auth.rate_limit.ip_window", a.RateLimit.IPWindow > 0)
	req("auth.rate_limit.identity_max_attempts", a.RateLimit.IdentityMaxAttempts > 0)
	req("auth.rate_limit.identity_window", a.RateLimit.IdentityWindow > 0)
	req("auth.mfa.otp_ttl", a.MFA.OTPTTL > 0)
	req("auth.mfa.otp_max_attempts", a.MFA.OTPMaxAttempts > 0)
	req("auth.mfa.otp_resend_rate_limit", a.MFA.OTPResendRateLimit > 0)
	req("auth.mfa.otp_resend_window", a.MFA.OTPResendWindow > 0)
	req("auth.mfa.enrollment_window", a.MFA.EnrollmentWindow > 0)
	req("auth.mfa.recovery_code_count", a.MFA.RecoveryCodeCount > 0)
	req("auth.device.trust_duration", a.Device.TrustDuration > 0)
	req("auth.device.fingerprint_version", a.Device.FingerprintVersion > 0)
	req("auth.fido2.rp_id", a.FIDO2.RPID != "")
	req("auth.fido2.rp_name", a.FIDO2.RPName != "")
	req("auth.fido2.rp_origin", a.FIDO2.RPOrigin != "")
	req("auth.fido2.user_verification", a.FIDO2.UserVerification != "")
	req("auth.fido2.attestation", a.FIDO2.Attestation != "")
	req("auth.fido2.challenge_ttl", a.FIDO2.ChallengeTTL > 0)

	req("kafka.brokers", len(c.Kafka.Brokers) > 0)
	req("kafka.outbox_topic", c.Kafka.OutboxTopic != "")
	req("kafka.publish_interval", c.Kafka.PublishInterval > 0)
	req("kafka.batch_size", c.Kafka.BatchSize > 0)

	if len(missing) > 0 {
		return fmt.Errorf("config: required keys are unset or zero (set them in the yaml file or via %s env vars): %s",
			envPrefix, strings.Join(missing, ", "))
	}
	return nil
}
