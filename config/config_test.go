package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfig copies the committed config.yaml into a temp file, applying
// edit to its contents first.
func writeConfig(t *testing.T, edit func(string) string) string {
	t.Helper()
	base, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(edit(string(base))), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoad_CommittedYAML(t *testing.T) {
	cfg, err := Load("config.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.Token.AccessTTL != 15*time.Minute {
		t.Errorf("auth.token.access_ttl = %v, want 15m", cfg.Auth.Token.AccessTTL)
	}
	if cfg.Auth.Argon2id.MemoryKB != 65536 {
		t.Errorf("auth.argon2id.memory_kb = %d, want 65536", cfg.Auth.Argon2id.MemoryKB)
	}
	if len(cfg.Kafka.Brokers) != 1 {
		t.Errorf("kafka.brokers = %v, want one broker", cfg.Kafka.Brokers)
	}
}

func TestLoad_EnvOverridesYAML(t *testing.T) {
	t.Setenv("ARAQUANID_POSTGRES__MAX_CONNS", "42")
	t.Setenv("ARAQUANID_POSTGRES__PASSWORD", "s3cret")
	t.Setenv("ARAQUANID_AUTH__SESSION__IDLE_TIMEOUT_WEB", "1m")
	// Not app config; must be ignored rather than rejected.
	t.Setenv("ARAQUANID_MIGRATE_DATABASE_URL", "postgres://x")

	cfg, err := Load("config.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Postgres.MaxConns != 42 {
		t.Errorf("postgres.max_conns = %d, want 42", cfg.Postgres.MaxConns)
	}
	if cfg.Postgres.Password != "s3cret" {
		t.Errorf("postgres.password = %q, want env value", cfg.Postgres.Password)
	}
	if cfg.Auth.Session.IdleTimeoutWeb != time.Minute {
		t.Errorf("auth.session.idle_timeout_web = %v, want 1m", cfg.Auth.Session.IdleTimeoutWeb)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("expected an error when the yaml file does not exist")
	}
}

func TestLoad_UnknownKey(t *testing.T) {
	path := writeConfig(t, func(s string) string {
		return strings.Replace(s, "max_conns: 10", "max_cons: 10", 1)
	})
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "max_cons") {
		t.Fatalf("expected an unknown-key error naming max_cons, got %v", err)
	}
}

func TestLoad_MissingRequiredKeys(t *testing.T) {
	path := writeConfig(t, func(s string) string {
		s = strings.Replace(s, "    access_ttl: 15m\n", "", 1)
		return strings.Replace(s, "    time_cost: 3\n", "", 1)
	})
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error for missing required keys")
	}
	for _, key := range []string{"auth.token.access_ttl", "auth.argon2id.time_cost"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not name %s", err, key)
		}
	}
}

// A required key missing from yaml is satisfied when env supplies it.
func TestLoad_EnvSuppliesRequiredKey(t *testing.T) {
	path := writeConfig(t, func(s string) string {
		return strings.Replace(s, "    access_ttl: 15m\n", "", 1)
	})
	t.Setenv("ARAQUANID_AUTH__TOKEN__ACCESS_TTL", "20m")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.Token.AccessTTL != 20*time.Minute {
		t.Errorf("auth.token.access_ttl = %v, want 20m", cfg.Auth.Token.AccessTTL)
	}
}
