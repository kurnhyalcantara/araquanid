package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
)

var credT0 = time.Date(2026, 6, 30, 9, 0, 0, 0, time.UTC)

var testAttempt = AttemptContext{
	CompanyCode:       "ACME01",
	IP:                netip.MustParseAddr("203.0.113.42"),
	UserAgent:         "Mozilla/5.0",
	DeviceFingerprint: "fp_hash_abc",
}

const day = 24 * time.Hour

// hashOf builds a deterministic fake hash for a plaintext password. Real
// Argon2id hashing lives outside the domain.
func hashOf(t *testing.T, plain string) PasswordHash {
	t.Helper()
	h, err := NewPasswordHash("h:"+plain, "salt:"+plain, PasswordArgon2id, 1)
	if err != nil {
		t.Fatalf("NewPasswordHash: %v", err)
	}
	return h
}

// matches stands in for a salted Argon2id comparison of plain against a
// stored hash.
func matches(plain string) PasswordMatcher {
	return func(stored PasswordHash) bool { return stored.Hash() == "h:"+plain }
}

func newTestCredential(t *testing.T) *Credential {
	t.Helper()
	c, err := NewCredential(NewCredentialParams{
		ID:       "cred-1",
		Identity: "identity-1",
		Password: hashOf(t, "Initial#Pass1"),
		Policy:   DefaultCredentialPolicy(),
		Now:      credT0,
	})
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return c
}

func failN(t *testing.T, c *Credential, n int, at time.Time) {
	t.Helper()
	for i := range n {
		if err := c.RecordFailedAttempt(testAttempt, DefaultLockoutPolicy(), at); err != nil {
			t.Fatalf("RecordFailedAttempt #%d: %v", i+1, err)
		}
	}
}

// lockPermanently walks the default escalation (30m, 2h, permanent) and
// returns the instant of the third lock.
func lockPermanently(t *testing.T, c *Credential) time.Time {
	t.Helper()
	first := credT0
	second := first.Add(30 * time.Minute)
	third := second.Add(2 * time.Hour)
	failN(t, c, 5, first)
	failN(t, c, 5, second)
	failN(t, c, 5, third)
	return third
}

func eventTypes(evs []DomainEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.EventType()
	}
	return out
}

func timeEq(got *time.Time, want time.Time) bool { return got != nil && got.Equal(want) }

// ---------------------------------------------------------------------------
// Value objects & policies
// ---------------------------------------------------------------------------

func TestNewPasswordHash_Validation(t *testing.T) {
	tests := []struct {
		name       string
		hash, salt string
		alg        PasswordAlgorithm
		version    int
		wantErr    bool
	}{
		{"valid argon2id", "h", "s", PasswordArgon2id, 1, false},
		{"valid legacy bcrypt", "h", "s", PasswordBcrypt, 1, false},
		{"empty hash", "", "s", PasswordArgon2id, 1, true},
		{"empty salt", "h", "", PasswordArgon2id, 1, true},
		{"unknown algorithm", "h", "s", "md5", 1, true},
		{"version below 1", "h", "s", PasswordArgon2id, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewPasswordHash(tt.hash, tt.salt, tt.alg, tt.version)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidPasswordHash) {
					t.Fatalf("err = %v, want ErrInvalidPasswordHash", err)
				}
				return
			}
			if err != nil || h.IsZero() {
				t.Fatalf("err = %v, zero = %v", err, h.IsZero())
			}
			if h.Hash() != tt.hash || h.Salt() != tt.salt || h.Algorithm() != tt.alg || h.Version() != tt.version {
				t.Errorf("getters mismatch: %+v", h)
			}
		})
	}
}

func TestLockoutPolicy_Validate(t *testing.T) {
	if err := DefaultLockoutPolicy().Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
	tests := []struct {
		name string
		p    LockoutPolicy
	}{
		{"zero threshold", LockoutPolicy{Threshold: 0, Window: time.Minute}},
		{"zero window", LockoutPolicy{Threshold: 5, Window: 0}},
		{"non-positive tier", LockoutPolicy{Threshold: 5, Window: time.Minute, TemporaryDurations: []time.Duration{0}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Validate(); !errors.Is(err, ErrInvalidLockoutPolicy) {
				t.Errorf("err = %v, want ErrInvalidLockoutPolicy", err)
			}
		})
	}
}

func TestCredentialPolicy_Validate(t *testing.T) {
	for _, p := range []CredentialPolicy{DefaultCredentialPolicy(), {HistoryDepth: 0, MaxAge: 0}} {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v: unexpected error %v", p, err)
		}
	}
	for _, p := range []CredentialPolicy{{HistoryDepth: -1}, {HistoryDepth: 12, MaxAge: -day}} {
		if err := p.Validate(); !errors.Is(err, ErrInvalidCredentialPolicy) {
			t.Errorf("%+v: err = %v, want ErrInvalidCredentialPolicy", p, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

func TestNewCredential(t *testing.T) {
	c := newTestCredential(t)

	if c.LockoutStatus() != LockoutUnlocked || c.FailedAttemptCount() != 0 || c.LockoutHistoryCount() != 0 {
		t.Errorf("new credential must be unlocked with zero counters")
	}
	if c.ForcePasswordChange() || c.RequiresPasswordChange(credT0) {
		t.Error("new credential must not require a password change")
	}
	if !c.PasswordCreatedAt().Equal(credT0) {
		t.Errorf("PasswordCreatedAt = %v, want %v", c.PasswordCreatedAt(), credT0)
	}
	if !timeEq(c.PasswordExpiresAt(), credT0.Add(180*day)) {
		t.Errorf("PasswordExpiresAt = %v, want +180d", c.PasswordExpiresAt())
	}
	if len(c.PasswordHistory()) != 0 {
		t.Error("new credential must have empty history")
	}
	if len(c.PullEvents()) != 0 {
		t.Error("creation must not record events")
	}
}

func TestNewCredential_NoExpiryAndForcedChange(t *testing.T) {
	c, err := NewCredential(NewCredentialParams{
		ID: "cred-1", Identity: "identity-1", Password: hashOf(t, "Initial#Pass1"),
		Policy: CredentialPolicy{HistoryDepth: 12, MaxAge: 0}, ForceChange: true, Now: credT0,
	})
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	if c.PasswordExpiresAt() != nil || c.IsPasswordExpired(credT0.Add(3650*day)) {
		t.Error("MaxAge 0 must mean the password never expires")
	}
	if !c.RequiresPasswordChange(credT0) {
		t.Error("ForceChange must require a password change")
	}
}

func TestNewCredential_Validation(t *testing.T) {
	valid := NewCredentialParams{
		ID: "cred-1", Identity: "identity-1", Password: hashOf(t, "x"),
		Policy: DefaultCredentialPolicy(), Now: credT0,
	}
	tests := []struct {
		name    string
		mutate  func(*NewCredentialParams)
		wantErr error
	}{
		{"missing id", func(p *NewCredentialParams) { p.ID = "" }, ErrInvalidCredential},
		{"missing identity", func(p *NewCredentialParams) { p.Identity = "" }, ErrInvalidCredential},
		{"zero password", func(p *NewCredentialParams) { p.Password = PasswordHash{} }, ErrInvalidCredential},
		{"zero time", func(p *NewCredentialParams) { p.Now = time.Time{} }, ErrInvalidCredential},
		{"invalid policy", func(p *NewCredentialParams) { p.Policy.HistoryDepth = -1 }, ErrInvalidCredentialPolicy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := valid
			tt.mutate(&p)
			if _, err := NewCredential(p); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Failed attempts & lockout (FR-LOGIN-003/004, US-003)
// ---------------------------------------------------------------------------

func TestRecordFailedAttempt_EmitsLoginFailed(t *testing.T) {
	c := newTestCredential(t)
	failN(t, c, 2, credT0)

	if c.FailedAttemptCount() != 2 || !timeEq(c.LastFailedAt(), credT0) {
		t.Fatalf("count=%d lastFailedAt=%v", c.FailedAttemptCount(), c.LastFailedAt())
	}
	evs := c.PullEvents()
	if got := eventTypes(evs); !slices.Equal(got, []string{"auth.LoginFailed", "auth.LoginFailed"}) {
		t.Fatalf("events = %v", got)
	}
	e := evs[1].(LoginFailed)
	if e.Reason != FailureInvalidCredentials || e.FailedAttemptCount != 2 ||
		e.IdentityID != "identity-1" || e.CompanyCode != "ACME01" ||
		e.IPAddress != testAttempt.IP || e.DeviceFingerprint != "fp_hash_abc" {
		t.Errorf("unexpected event %+v", e)
	}
}

func TestRecordFailedAttempt_Window(t *testing.T) {
	t.Run("gap beyond window resets counter", func(t *testing.T) {
		c := newTestCredential(t)
		failN(t, c, 4, credT0)
		failN(t, c, 1, credT0.Add(16*time.Minute))
		if c.FailedAttemptCount() != 1 || c.LockoutStatus() != LockoutUnlocked {
			t.Errorf("count=%d status=%s, want 1/UNLOCKED", c.FailedAttemptCount(), c.LockoutStatus())
		}
	})
	t.Run("within window accumulates and locks", func(t *testing.T) {
		c := newTestCredential(t)
		failN(t, c, 4, credT0)
		failN(t, c, 1, credT0.Add(14*time.Minute))
		if c.LockoutStatus() != LockoutTemporary {
			t.Errorf("status=%s, want LOCKED_TEMPORARY", c.LockoutStatus())
		}
	})
}

func TestRecordFailedAttempt_LocksAtThreshold(t *testing.T) {
	c := newTestCredential(t)
	failN(t, c, 5, credT0)

	wantUntil := credT0.Add(30 * time.Minute)
	if c.LockoutStatus() != LockoutTemporary || !timeEq(c.LockedAt(), credT0) || !timeEq(c.LockedUntil(), wantUntil) {
		t.Fatalf("status=%s lockedAt=%v lockedUntil=%v", c.LockoutStatus(), c.LockedAt(), c.LockedUntil())
	}
	if c.FailedAttemptCount() != 5 || c.LockoutHistoryCount() != 1 {
		t.Errorf("count=%d lockoutHistoryCount=%d, want 5/1", c.FailedAttemptCount(), c.LockoutHistoryCount())
	}

	evs := c.PullEvents()
	want := append(slices.Repeat([]string{"auth.LoginFailed"}, 5), "auth.AccountLocked")
	if got := eventTypes(evs); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	locked := evs[5].(AccountLocked)
	if locked.LockoutType != LockoutTemporary || !timeEq(locked.LockedUntil, wantUntil) ||
		locked.TriggerIP != testAttempt.IP || locked.FailedAttemptCount != 5 || locked.IdentityID != "identity-1" {
		t.Errorf("unexpected AccountLocked %+v", locked)
	}
}

func TestLockoutEscalation(t *testing.T) {
	c := newTestCredential(t)

	failN(t, c, 5, credT0)
	if !timeEq(c.LockedUntil(), credT0.Add(30*time.Minute)) {
		t.Fatalf("1st lock until %v, want +30m", c.LockedUntil())
	}

	second := credT0.Add(30 * time.Minute) // temp lock elapsed -> auto-unlock on next attempt
	failN(t, c, 5, second)
	if c.LockoutStatus() != LockoutTemporary || !timeEq(c.LockedUntil(), second.Add(2*time.Hour)) || c.LockoutHistoryCount() != 2 {
		t.Fatalf("2nd lock: status=%s until=%v count=%d", c.LockoutStatus(), c.LockedUntil(), c.LockoutHistoryCount())
	}

	third := second.Add(2 * time.Hour)
	failN(t, c, 5, third)
	if c.LockoutStatus() != LockoutPermanent || c.LockedUntil() != nil || c.LockoutHistoryCount() != 3 {
		t.Fatalf("3rd lock: status=%s until=%v count=%d", c.LockoutStatus(), c.LockedUntil(), c.LockoutHistoryCount())
	}
	evs := c.PullEvents()
	last := evs[len(evs)-1].(AccountLocked)
	if last.LockoutType != LockoutPermanent || last.LockedUntil != nil {
		t.Errorf("unexpected AccountLocked %+v", last)
	}
}

func TestLockedCredential_CannotBeVerified(t *testing.T) {
	c := newTestCredential(t)
	failN(t, c, 5, credT0)
	c.PullEvents()
	during := credT0.Add(10 * time.Minute)

	if !c.IsLocked(during) {
		t.Error("IsLocked must be true during the lock")
	}
	if err := c.EnsureVerifiable(during); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("EnsureVerifiable err = %v, want ErrAccountLocked", err)
	}
	if err := c.RecordSuccessfulVerification(during); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("RecordSuccessfulVerification err = %v, want ErrAccountLocked", err)
	}

	err := c.RecordFailedAttempt(testAttempt, DefaultLockoutPolicy(), during)
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("RecordFailedAttempt err = %v, want ErrAccountLocked", err)
	}
	if c.FailedAttemptCount() != 5 {
		t.Errorf("count = %d, must not grow while locked", c.FailedAttemptCount())
	}
	evs := c.PullEvents()
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %v", eventTypes(evs))
	}
	if e := evs[0].(LoginFailed); e.Reason != FailureAccountLocked {
		t.Errorf("reason = %s, want ACCOUNT_LOCKED", e.Reason)
	}
}

func TestTemporaryLock_AutoUnlocks(t *testing.T) {
	c := newTestCredential(t)
	failN(t, c, 5, credT0)
	c.PullEvents()
	until := *c.LockedUntil()

	if !c.IsLocked(until.Add(-time.Nanosecond)) || c.IsLocked(until) {
		t.Fatal("lock must end exactly at locked_until")
	}
	if c.LockoutStatus() != LockoutTemporary {
		t.Fatal("IsLocked must not mutate state")
	}

	if err := c.EnsureVerifiable(until); err != nil {
		t.Fatalf("EnsureVerifiable: %v", err)
	}
	if c.LockoutStatus() != LockoutUnlocked || c.FailedAttemptCount() != 0 ||
		c.LockedAt() != nil || c.LockedUntil() != nil {
		t.Errorf("auto-unlock must clear lock state and reset counter")
	}
	if c.LockoutHistoryCount() != 1 {
		t.Errorf("LockoutHistoryCount = %d, must survive unlock for escalation", c.LockoutHistoryCount())
	}
	evs := c.PullEvents()
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %v", eventTypes(evs))
	}
	if e := evs[0].(AccountUnlocked); e.UnlockedBy != "" || e.PreviousLockoutType != LockoutTemporary || !e.At.Equal(until) {
		t.Errorf("unexpected auto-unlock event %+v", e)
	}
}

func TestPermanentLock_RequiresAdmin(t *testing.T) {
	c := newTestCredential(t)
	third := lockPermanently(t, c)
	c.PullEvents()
	far := third.Add(365 * day)

	if err := c.EnsureVerifiable(far); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("permanent lock must never auto-unlock, err = %v", err)
	}
	if err := c.Unlock("admin-1", far); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if c.LockoutStatus() != LockoutUnlocked || c.FailedAttemptCount() != 0 || c.LockoutHistoryCount() != 3 {
		t.Errorf("status=%s count=%d lockoutHistoryCount=%d", c.LockoutStatus(), c.FailedAttemptCount(), c.LockoutHistoryCount())
	}
	evs := c.PullEvents()
	if e, ok := evs[len(evs)-1].(AccountUnlocked); !ok || e.UnlockedBy != "admin-1" || e.PreviousLockoutType != LockoutPermanent {
		t.Errorf("unexpected events %v", eventTypes(evs))
	}
}

func TestUnlock_NotLocked(t *testing.T) {
	c := newTestCredential(t)
	if err := c.Unlock("admin-1", credT0); !errors.Is(err, ErrAccountNotLocked) {
		t.Errorf("err = %v, want ErrAccountNotLocked", err)
	}
	if len(c.PullEvents()) != 0 {
		t.Error("rejected unlock must not record events")
	}
}

func TestRecordSuccessfulVerification_ResetsCounter(t *testing.T) {
	c := newTestCredential(t)
	failN(t, c, 3, credT0)

	if err := c.RecordSuccessfulVerification(credT0.Add(time.Minute)); err != nil {
		t.Fatalf("RecordSuccessfulVerification: %v", err)
	}
	if c.FailedAttemptCount() != 0 || c.LastFailedAt() != nil {
		t.Fatalf("count=%d lastFailedAt=%v, want reset", c.FailedAttemptCount(), c.LastFailedAt())
	}
	// Counter is truly consecutive: 4 more failures must not lock.
	failN(t, c, 4, credT0.Add(2*time.Minute))
	if c.LockoutStatus() != LockoutUnlocked {
		t.Error("success must reset the consecutive-failure counter")
	}
}

// ---------------------------------------------------------------------------
// Password lifecycle (FR-PWD-002/003/005/006/007, US-007)
// ---------------------------------------------------------------------------

func TestChangePassword(t *testing.T) {
	c := newTestCredential(t)
	old := c.Password()
	now := credT0.Add(day)
	newHash := hashOf(t, "New#Pass2")

	if err := c.ChangePassword(newHash, matches("New#Pass2"), "identity-1", DefaultCredentialPolicy(), now); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if c.Password() != newHash || !c.PasswordCreatedAt().Equal(now) || !timeEq(c.PasswordExpiresAt(), now.Add(180*day)) {
		t.Errorf("password state not updated: %+v", c.Snapshot())
	}
	hist := c.PasswordHistory()
	if len(hist) != 1 || hist[0].Hash != old || !hist[0].CreatedAt.Equal(now) {
		t.Errorf("history = %+v, want [old password @ now]", hist)
	}
	evs := c.PullEvents()
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %v", eventTypes(evs))
	}
	e := evs[0].(PasswordChanged)
	if e.ChangedBy != "identity-1" || e.ChangeType != ChangeUserInitiated || e.IdentityID != "identity-1" {
		t.Errorf("unexpected event %+v", e)
	}
}

func TestChangePassword_RejectsReuse(t *testing.T) {
	c := newTestCredential(t)
	policy := DefaultCredentialPolicy()

	if err := c.ChangePassword(hashOf(t, "Initial#Pass1"), matches("Initial#Pass1"), "identity-1", policy, credT0); !errors.Is(err, ErrPasswordReused) {
		t.Fatalf("reusing current: err = %v, want ErrPasswordReused", err)
	}
	if err := c.ChangePassword(hashOf(t, "B#Pass2"), matches("B#Pass2"), "identity-1", policy, credT0.Add(time.Hour)); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	c.PullEvents()
	before := c.Snapshot()

	if err := c.ChangePassword(hashOf(t, "Initial#Pass1"), matches("Initial#Pass1"), "identity-1", policy, credT0.Add(2*time.Hour)); !errors.Is(err, ErrPasswordReused) {
		t.Fatalf("reusing history: err = %v, want ErrPasswordReused", err)
	}
	if !reflect.DeepEqual(before, c.Snapshot()) || len(c.PullEvents()) != 0 {
		t.Error("rejected change must not mutate state or record events")
	}
}

func TestChangePassword_HistoryDepthNeverExceedsPolicy(t *testing.T) {
	c := newTestCredential(t)
	policy := CredentialPolicy{HistoryDepth: 3, MaxAge: 90 * day}

	for i := 1; i <= 5; i++ {
		pw := fmt.Sprintf("Pass#%d", i)
		if err := c.ChangePassword(hashOf(t, pw), matches(pw), "identity-1", policy, credT0.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatalf("change %d: %v", i, err)
		}
		if n := len(c.PasswordHistory()); n > policy.HistoryDepth {
			t.Fatalf("history depth %d exceeds policy %d", n, policy.HistoryDepth)
		}
	}

	hist := c.PasswordHistory()
	want := []string{"h:Pass#4", "h:Pass#3", "h:Pass#2"} // newest first
	got := []string{hist[0].Hash.Hash(), hist[1].Hash.Hash(), hist[2].Hash.Hash()}
	if !slices.Equal(got, want) {
		t.Errorf("history = %v, want %v", got, want)
	}
	// Dropped out of history -> reusable again.
	if err := c.ChangePassword(hashOf(t, "Initial#Pass1"), matches("Initial#Pass1"), "identity-1", policy, credT0.Add(6*time.Hour)); err != nil {
		t.Errorf("password beyond history depth must be reusable: %v", err)
	}
}

func TestChangePassword_ForcedType(t *testing.T) {
	t.Run("after admin force", func(t *testing.T) {
		c := newTestCredential(t)
		if err := c.MarkForcePasswordChange("admin-1", credT0); err != nil {
			t.Fatalf("MarkForcePasswordChange: %v", err)
		}
		c.PullEvents()
		if err := c.ChangePassword(hashOf(t, "New#Pass2"), matches("New#Pass2"), "identity-1", DefaultCredentialPolicy(), credT0.Add(time.Hour)); err != nil {
			t.Fatalf("ChangePassword: %v", err)
		}
		if c.ForcePasswordChange() || c.RequiresPasswordChange(credT0.Add(time.Hour)) {
			t.Error("change must clear the force flag")
		}
		if e := c.PullEvents()[0].(PasswordChanged); e.ChangeType != ChangeForced {
			t.Errorf("ChangeType = %s, want FORCED", e.ChangeType)
		}
	})
	t.Run("after expiry", func(t *testing.T) {
		c := newTestCredential(t)
		if err := c.ChangePassword(hashOf(t, "New#Pass2"), matches("New#Pass2"), "identity-1", DefaultCredentialPolicy(), credT0.Add(181*day)); err != nil {
			t.Fatalf("ChangePassword: %v", err)
		}
		if e := c.PullEvents()[0].(PasswordChanged); e.ChangeType != ChangeForced {
			t.Errorf("ChangeType = %s, want FORCED", e.ChangeType)
		}
	})
}

func TestChangePassword_WhenLocked(t *testing.T) {
	c := newTestCredential(t)
	failN(t, c, 5, credT0)
	err := c.ChangePassword(hashOf(t, "New#Pass2"), matches("New#Pass2"), "identity-1", DefaultCredentialPolicy(), credT0.Add(time.Minute))
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("err = %v, want ErrAccountLocked", err)
	}
}

func TestResetPassword(t *testing.T) {
	policy := DefaultCredentialPolicy()

	t.Run("success", func(t *testing.T) {
		c := newTestCredential(t)
		_ = c.MarkForcePasswordChange("admin-1", credT0)
		c.PullEvents()

		if err := c.ResetPassword(hashOf(t, "Reset#Pass2"), matches("Reset#Pass2"), policy, credT0.Add(time.Hour)); err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}
		if c.ForcePasswordChange() || len(c.PasswordHistory()) != 1 {
			t.Errorf("force=%v history=%d", c.ForcePasswordChange(), len(c.PasswordHistory()))
		}
		if got := eventTypes(c.PullEvents()); !slices.Equal(got, []string{"auth.PasswordResetCompleted"}) {
			t.Errorf("events = %v", got)
		}
	})
	t.Run("rejects reuse", func(t *testing.T) {
		c := newTestCredential(t)
		if err := c.ResetPassword(hashOf(t, "Initial#Pass1"), matches("Initial#Pass1"), policy, credT0); !errors.Is(err, ErrPasswordReused) {
			t.Errorf("err = %v, want ErrPasswordReused", err)
		}
	})
	t.Run("allowed under temporary lock, lock kept", func(t *testing.T) {
		c := newTestCredential(t)
		failN(t, c, 5, credT0)
		if err := c.ResetPassword(hashOf(t, "Reset#Pass2"), matches("Reset#Pass2"), policy, credT0.Add(time.Minute)); err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}
		if c.LockoutStatus() != LockoutTemporary {
			t.Errorf("status = %s, reset must not lift the lock", c.LockoutStatus())
		}
	})
	t.Run("rejected under permanent lock", func(t *testing.T) {
		c := newTestCredential(t)
		third := lockPermanently(t, c)
		if err := c.ResetPassword(hashOf(t, "Reset#Pass2"), matches("Reset#Pass2"), policy, third.Add(time.Minute)); !errors.Is(err, ErrAccountLocked) {
			t.Errorf("err = %v, want ErrAccountLocked", err)
		}
	})
}

func TestMarkForcePasswordChange(t *testing.T) {
	c := newTestCredential(t)

	if err := c.MarkForcePasswordChange("admin-1", credT0); err != nil {
		t.Fatalf("MarkForcePasswordChange: %v", err)
	}
	if !c.ForcePasswordChange() || !c.RequiresPasswordChange(credT0) {
		t.Error("flag must be set and require a change")
	}
	// US-007: the user can still log in with the current password.
	if err := c.EnsureVerifiable(credT0); err != nil {
		t.Errorf("forced change must not block verification: %v", err)
	}

	_ = c.MarkForcePasswordChange("admin-1", credT0.Add(time.Minute)) // idempotent
	evs := c.PullEvents()
	if len(evs) != 1 {
		t.Fatalf("want exactly 1 event, got %v", eventTypes(evs))
	}
	if e := evs[0].(AdminInitiatedPasswordReset); e.InitiatedBy != "admin-1" {
		t.Errorf("InitiatedBy = %q, want admin-1", e.InitiatedBy)
	}
}

func TestPasswordExpiry(t *testing.T) {
	c := newTestCredential(t)
	exp := *c.PasswordExpiresAt()

	if c.IsPasswordExpired(exp.Add(-time.Nanosecond)) || c.RequiresPasswordChange(exp.Add(-time.Nanosecond)) {
		t.Error("password must be valid before expires_at")
	}
	if !c.IsPasswordExpired(exp) || !c.RequiresPasswordChange(exp) {
		t.Error("password must be expired at expires_at and require a change")
	}
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func TestCredentialSnapshotRoundTrip(t *testing.T) {
	c := newTestCredential(t)
	_ = c.ChangePassword(hashOf(t, "B#Pass2"), matches("B#Pass2"), "identity-1", DefaultCredentialPolicy(), credT0.Add(time.Hour))
	failN(t, c, 5, credT0.Add(2*time.Hour))

	got, err := RehydrateCredential(c.Snapshot(), DefaultCredentialPolicy())
	if err != nil {
		t.Fatalf("RehydrateCredential: %v", err)
	}
	if !reflect.DeepEqual(got.Snapshot(), c.Snapshot()) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got.Snapshot(), c.Snapshot())
	}
	if len(got.PullEvents()) != 0 {
		t.Error("rehydration must not record events")
	}
}

func TestRehydrateCredential_RejectsInconsistentState(t *testing.T) {
	at := credT0.Add(time.Minute)
	base := newTestCredential(t).Snapshot()

	tests := []struct {
		name   string
		mutate func(*CredentialSnapshot)
	}{
		{"unlocked with locked_until", func(s *CredentialSnapshot) { s.LockedUntil = &at }},
		{"unlocked with locked_at", func(s *CredentialSnapshot) { s.LockedAt = &at }},
		{"temporary without locked_until", func(s *CredentialSnapshot) {
			s.LockoutStatus, s.LockedAt, s.LockoutHistoryCount = LockoutTemporary, &at, 1
		}},
		{"locked without locked_at", func(s *CredentialSnapshot) {
			s.LockoutStatus, s.LockoutHistoryCount = LockoutPermanent, 3
		}},
		{"permanent with locked_until", func(s *CredentialSnapshot) {
			s.LockoutStatus, s.LockedAt, s.LockedUntil, s.LockoutHistoryCount = LockoutPermanent, &at, &at, 3
		}},
		{"locked with zero lockout count", func(s *CredentialSnapshot) {
			s.LockoutStatus, s.LockedAt, s.LockedUntil = LockoutTemporary, &at, &at
		}},
		{"unknown lockout status", func(s *CredentialSnapshot) { s.LockoutStatus = "FROZEN" }},
		{"negative failed count", func(s *CredentialSnapshot) { s.FailedAttemptCount = -1 }},
		{"zero password hash", func(s *CredentialSnapshot) { s.Password = PasswordHash{} }},
		{"history exceeds policy depth", func(s *CredentialSnapshot) {
			s.History = make([]PasswordHistoryEntry, DefaultCredentialPolicy().HistoryDepth+1)
			for i := range s.History {
				s.History[i] = PasswordHistoryEntry{Hash: hashOf(t, fmt.Sprint(i)), CreatedAt: credT0}
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := base
			tt.mutate(&snap)
			if _, err := RehydrateCredential(snap, DefaultCredentialPolicy()); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}
