package usecase

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kurnhyalcantara/araquanid/internal/apperror"
	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
	"github.com/kurnhyalcantara/araquanid/internal/platform/jwtsign"
	"github.com/kurnhyalcantara/araquanid/internal/platform/passwordhash"
)

// --- test doubles -----------------------------------------------------

var testArgon2id = passwordhash.Argon2idParams{TimeCost: 1, MemoryKB: 8 * 1024, Parallelism: 1}

func newTestCredential(t *testing.T, identityID, password string, forceChange bool, now time.Time) *domain.Credential {
	t.Helper()
	hash, salt, err := passwordhash.Hash(password, testArgon2id)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	ph, err := domain.NewPasswordHash(hash, salt, domain.PasswordArgon2id, 1)
	if err != nil {
		t.Fatalf("NewPasswordHash: %v", err)
	}
	cred, err := domain.NewCredential(domain.NewCredentialParams{
		ID: domain.CredentialID(identityID + "-cred"), Identity: domain.IdentityRef(identityID),
		Password: ph, Policy: domain.DefaultCredentialPolicy(), ForceChange: forceChange, Now: now,
	})
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return cred
}

type fakeRepo struct {
	credentials map[string]*domain.Credential
	devices     map[string]*repository.RegisteredDevice // key: identityID+"|"+fingerprint
	hasFactor   map[string]bool
	factors     map[string][]domain.FactorType
	sessions    map[string][]*domain.AuthenticationSession // key: identityID+"|"+clientID

	attempts   []repository.LoginAttemptRecord
	events     []domain.DomainEvent
	registered []string // identityID+"|"+fingerprint of newly-registered devices
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		credentials: map[string]*domain.Credential{},
		devices:     map[string]*repository.RegisteredDevice{},
		hasFactor:   map[string]bool{},
		factors:     map[string][]domain.FactorType{},
		sessions:    map[string][]*domain.AuthenticationSession{},
	}
}

func (r *fakeRepo) FindByIdentity(_ context.Context, identityID string) (*domain.Credential, error) {
	c, ok := r.credentials[identityID]
	if !ok {
		return nil, domain.ErrCredentialNotFound
	}
	return c, nil
}

func (r *fakeRepo) FindByFingerprint(_ context.Context, identityID, fingerprintHash string) (*repository.RegisteredDevice, error) {
	return r.devices[identityID+"|"+fingerprintHash], nil
}

func (r *fakeRepo) ListActiveFactorTypes(_ context.Context, identityID string) ([]domain.FactorType, error) {
	return r.factors[identityID], nil
}

func (r *fakeRepo) HasActiveFactor(_ context.Context, identityID string) (bool, error) {
	return r.hasFactor[identityID], nil
}

func (r *fakeRepo) Record(_ context.Context, a repository.LoginAttemptRecord) error {
	r.attempts = append(r.attempts, a)
	return nil
}

func (r *fakeRepo) Execute(ctx context.Context, fn func(ctx context.Context, tx repository.TxRepositories) error) error {
	return fn(ctx, repository.TxRepositories{
		Credentials:   r,
		Sessions:      r,
		RefreshTokens: r,
		Devices:       r,
		LoginAttempts: r,
		Outbox:        r,
	})
}

func (r *fakeRepo) Save(_ context.Context, c *domain.Credential) error {
	r.credentials[string(c.Identity())] = c
	return nil
}

func (r *fakeRepo) Create(_ context.Context, s *domain.AuthenticationSession, clientID string) error {
	key := string(s.Identity()) + "|" + clientID
	r.sessions[key] = append(r.sessions[key], s)
	return nil
}

func (r *fakeRepo) Revoke(_ context.Context, s *domain.AuthenticationSession) error { return nil }

func (r *fakeRepo) CountActive(_ context.Context, identityID, clientID string) (int, error) {
	return len(r.sessions[identityID+"|"+clientID]), nil
}

func (r *fakeRepo) FindOldestActive(_ context.Context, identityID, clientID string) (*domain.AuthenticationSession, error) {
	sessions := r.sessions[identityID+"|"+clientID]
	if len(sessions) == 0 {
		return nil, nil
	}
	return sessions[0], nil
}

func (r *fakeRepo) ListActive(_ context.Context, identityID, clientID string) ([]*domain.AuthenticationSession, error) {
	return r.sessions[identityID+"|"+clientID], nil
}

func (r *fakeRepo) CreateFamily(_ context.Context, familyID, sessionID, identityID string) error {
	return nil
}
func (r *fakeRepo) CreateToken(_ context.Context, rec repository.RefreshTokenRecord) error {
	return nil
}

func (r *fakeRepo) Register(_ context.Context, identityID, fingerprintHash string, _ int, _, _ string, _ time.Time) (string, error) {
	r.registered = append(r.registered, identityID+"|"+fingerprintHash)
	return "new-device-id", nil
}

func (r *fakeRepo) Touch(_ context.Context, deviceID string, _ time.Time) error { return nil }

func (r *fakeRepo) Append(_ context.Context, events []domain.DomainEvent) error {
	r.events = append(r.events, events...)
	return nil
}

type fakeIdentityACL struct {
	byIdentifier map[string]*repository.ResolvedIdentity
}

func (a *fakeIdentityACL) ResolveIdentity(_ context.Context, identifier, _ string) (*repository.ResolvedIdentity, bool, error) {
	ri, ok := a.byIdentifier[identifier]
	if !ok {
		return nil, false, nil
	}
	return ri, true, nil
}

type fakeRateLimiter struct{ deny bool }

func (f *fakeRateLimiter) Allow(_ context.Context, _ string, _ int, _ time.Duration) (bool, time.Duration, error) {
	if f.deny {
		return false, 30 * time.Second, nil
	}
	return true, 0, nil
}

type fakeMFASessionStore struct {
	created map[string]repository.MFASessionState
}

func (f *fakeMFASessionStore) Create(_ context.Context, token string, s repository.MFASessionState, _ time.Duration) error {
	if f.created == nil {
		f.created = map[string]repository.MFASessionState{}
	}
	f.created[token] = s
	return nil
}

type fakeTokenSigner struct{}

func (fakeTokenSigner) SignAccessToken(_ jwtsign.AccessTokenClaims, _ time.Duration) (string, error) {
	return "access-token", nil
}
func (fakeTokenSigner) SignRestrictedToken(_, _ string, _ time.Duration) (string, error) {
	return "restricted-token", nil
}

// --- test setup ---------------------------------------------------------

func newTestUsecase(t *testing.T, repo *fakeRepo, acl *fakeIdentityACL, rl *fakeRateLimiter, mfaStore *fakeMFASessionStore) *Usecase {
	t.Helper()
	return New(Dependencies{
		UnitOfWork:      repo,
		Credentials:     repo,
		Devices:         repo,
		MFAFactors:      repo,
		LoginAttempts:   repo,
		IdentityACL:     acl,
		MFASessionStore: mfaStore,
		RateLimiter:     rl,
		TokenSigner:     fakeTokenSigner{},
		Clock:           func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		NewID:           func() string { return "generated-id" },
		Config: Config{
			Lockout:            domain.DefaultLockoutPolicy(),
			CredentialPolicy:   domain.DefaultCredentialPolicy(),
			SessionPolicy:      domain.SessionPolicy{IdleTimeout: 15 * time.Minute, AbsoluteLifetime: 8 * time.Hour},
			ConcurrentPolicy:   "ALLOW_ALL",
			ConcurrentMax:      5,
			MFASessionWindow:   10 * time.Minute,
			ForcedChangeWindow: 5 * time.Minute,
			AccessTokenTTL:     15 * time.Minute,
			RefreshTokenTTL:    24 * time.Hour,
			Argon2id:           testArgon2id,
			FingerprintVersion: 1,
			RateLimit:          RateLimitConfig{IPMaxAttempts: 10, IPWindow: time.Minute, IdentityMaxAttempts: 10, IdentityWindow: time.Minute},
		},
	})
}

func baseInput() LoginInput {
	return LoginInput{
		Identifier:  "john.smith",
		Password:    "correct-horse",
		ClientID:    "web",
		CompanyCode: "ACME01",
		IP:          netip.MustParseAddr("203.0.113.1"),
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
	}
}

func errCode(t *testing.T, err error) apperror.Code {
	t.Helper()
	appErr, ok := err.(*apperror.Error)
	if !ok {
		t.Fatalf("expected *apperror.Error, got %T: %v", err, err)
	}
	return appErr.Code
}

// --- tests ---------------------------------------------------------------

func TestLogin_RateLimited(t *testing.T) {
	repo := newFakeRepo()
	uc := newTestUsecase(t, repo, &fakeIdentityACL{}, &fakeRateLimiter{deny: true}, &fakeMFASessionStore{})

	_, err := uc.Login(context.Background(), baseInput())
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := errCode(t, err); got != apperror.ErrRateLimited {
		t.Errorf("code = %v, want %v", got, apperror.ErrRateLimited)
	}
	if len(repo.attempts) != 1 || repo.attempts[0].Outcome != "RATE_LIMITED" {
		t.Errorf("expected one RATE_LIMITED attempt record, got %+v", repo.attempts)
	}
}

func TestLogin_IdentityNotFound(t *testing.T) {
	repo := newFakeRepo()
	uc := newTestUsecase(t, repo, &fakeIdentityACL{byIdentifier: map[string]*repository.ResolvedIdentity{}}, &fakeRateLimiter{}, &fakeMFASessionStore{})

	_, err := uc.Login(context.Background(), baseInput())
	if got := errCode(t, err); got != apperror.ErrLoginInvalidCredentials {
		t.Errorf("code = %v, want %v", got, apperror.ErrLoginInvalidCredentials)
	}
	if len(repo.attempts) != 1 || repo.attempts[0].Outcome != "FAILED_CREDENTIALS" || repo.attempts[0].IdentityID != nil {
		t.Errorf("expected one FAILED_CREDENTIALS attempt with no identity_id, got %+v", repo.attempts)
	}
}

func TestLogin_AccountLocked(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := newFakeRepo()
	cred := newTestCredential(t, "identity-1", "correct-horse", false, now)

	// Drive the credential into a temporary lock via repeated failures.
	policy := domain.DefaultLockoutPolicy()
	for i := 0; i < policy.Threshold; i++ {
		_ = cred.RecordFailedAttempt(domain.AttemptContext{IP: netip.MustParseAddr("203.0.113.1")}, policy, now)
	}
	if !cred.IsLocked(now) {
		t.Fatal("test setup: expected credential to be locked")
	}
	repo.credentials["identity-1"] = cred

	acl := &fakeIdentityACL{byIdentifier: map[string]*repository.ResolvedIdentity{
		"john.smith": {IdentityID: "identity-1", Status: "ACTIVE"},
	}}
	uc := newTestUsecase(t, repo, acl, &fakeRateLimiter{}, &fakeMFASessionStore{})

	_, err := uc.Login(context.Background(), baseInput())
	if got := errCode(t, err); got != apperror.ErrLoginAccountLocked {
		t.Errorf("code = %v, want %v", got, apperror.ErrLoginAccountLocked)
	}
	appErr := err.(*apperror.Error)
	if appErr.Details["locked_until"] == "" {
		t.Error("expected locked_until detail on a temporary lock")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := newFakeRepo()
	repo.credentials["identity-1"] = newTestCredential(t, "identity-1", "correct-horse", false, now)
	acl := &fakeIdentityACL{byIdentifier: map[string]*repository.ResolvedIdentity{
		"john.smith": {IdentityID: "identity-1", Status: "ACTIVE"},
	}}
	uc := newTestUsecase(t, repo, acl, &fakeRateLimiter{}, &fakeMFASessionStore{})

	in := baseInput()
	in.Password = "wrong-password"
	_, err := uc.Login(context.Background(), in)
	if got := errCode(t, err); got != apperror.ErrLoginInvalidCredentials {
		t.Errorf("code = %v, want %v", got, apperror.ErrLoginInvalidCredentials)
	}
	if repo.credentials["identity-1"].FailedAttemptCount() != 1 {
		t.Errorf("expected failed_attempt_count = 1, got %d", repo.credentials["identity-1"].FailedAttemptCount())
	}
	if len(repo.events) == 0 {
		t.Error("expected a LoginFailed event to be appended to the outbox")
	}
}

func TestLogin_CompletedNoMFA(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := newFakeRepo()
	repo.credentials["identity-1"] = newTestCredential(t, "identity-1", "correct-horse", false, now)
	repo.devices["identity-1|"+computeFingerprint("Mozilla/5.0 (Windows NT 10.0) Chrome/120", "", DeviceFingerprintInput{}, netip.MustParseAddr("203.0.113.1"))] =
		&repository.RegisteredDevice{ID: "device-1", TrustStatus: "REGISTERED", LastSeenAt: now}
	acl := &fakeIdentityACL{byIdentifier: map[string]*repository.ResolvedIdentity{
		"john.smith": {IdentityID: "identity-1", Status: "ACTIVE", CorporateID: "corp-1"},
	}}
	uc := newTestUsecase(t, repo, acl, &fakeRateLimiter{}, &fakeMFASessionStore{})

	result, err := uc.Login(context.Background(), baseInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AuthenticationResult != "COMPLETED" {
		t.Fatalf("authentication_result = %q, want COMPLETED", result.AuthenticationResult)
	}
	if result.AccessToken == "" || result.RefreshToken == "" || result.SessionID == "" {
		t.Errorf("expected tokens and session id to be populated: %+v", result)
	}
	if result.AAL != string(domain.AAL1) {
		t.Errorf("aal = %q, want AAL1", result.AAL)
	}
	if len(repo.sessions["identity-1|web"]) != 1 {
		t.Errorf("expected exactly one session to be created, got %d", len(repo.sessions["identity-1|web"]))
	}
	if len(repo.attempts) != 1 || repo.attempts[0].Outcome != "SUCCEEDED" {
		t.Errorf("expected one SUCCEEDED attempt, got %+v", repo.attempts)
	}
}

func TestLogin_MFARequiredWhenDeviceUnrecognized(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := newFakeRepo()
	repo.credentials["identity-1"] = newTestCredential(t, "identity-1", "correct-horse", false, now)
	// No registered_devices row for this fingerprint -> BR-003 "device unrecognized".
	acl := &fakeIdentityACL{byIdentifier: map[string]*repository.ResolvedIdentity{
		"john.smith": {IdentityID: "identity-1", Status: "ACTIVE"},
	}}
	mfaStore := &fakeMFASessionStore{}
	uc := newTestUsecase(t, repo, acl, &fakeRateLimiter{}, mfaStore)

	result, err := uc.Login(context.Background(), baseInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AuthenticationResult != "MFA_REQUIRED" {
		t.Fatalf("authentication_result = %q, want MFA_REQUIRED", result.AuthenticationResult)
	}
	if result.MFASessionToken == "" {
		t.Error("expected a non-empty mfa_session_token")
	}
	if len(mfaStore.created) != 1 {
		t.Errorf("expected exactly one mfa session to be created, got %d", len(mfaStore.created))
	}
	if len(repo.sessions) != 0 {
		t.Error("MFA_REQUIRED must not create a session")
	}
}

func TestLogin_ForcePasswordChange(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := newFakeRepo()
	repo.credentials["identity-1"] = newTestCredential(t, "identity-1", "correct-horse", true, now)
	acl := &fakeIdentityACL{byIdentifier: map[string]*repository.ResolvedIdentity{
		"john.smith": {IdentityID: "identity-1", Status: "ACTIVE"},
	}}
	uc := newTestUsecase(t, repo, acl, &fakeRateLimiter{}, &fakeMFASessionStore{})

	result, err := uc.Login(context.Background(), baseInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AuthenticationResult != "PASSWORD_CHANGE_REQUIRED" {
		t.Fatalf("authentication_result = %q, want PASSWORD_CHANGE_REQUIRED", result.AuthenticationResult)
	}
	if result.ForcedChangeSessionToken == "" {
		t.Error("expected a non-empty forced_change_session_token")
	}
	if !result.ForcePasswordChange {
		t.Error("expected force_password_change = true")
	}
}

func TestLogin_InactiveIdentityCollapsesToInvalidCredentials(t *testing.T) {
	repo := newFakeRepo()
	acl := &fakeIdentityACL{byIdentifier: map[string]*repository.ResolvedIdentity{
		"john.smith": {IdentityID: "identity-1", Status: "SUSPENDED"},
	}}
	uc := newTestUsecase(t, repo, acl, &fakeRateLimiter{}, &fakeMFASessionStore{})

	_, err := uc.Login(context.Background(), baseInput())
	if got := errCode(t, err); got != apperror.ErrLoginInvalidCredentials {
		t.Errorf("code = %v, want %v (FR-LOGIN-003: must be indistinguishable from invalid credentials)", got, apperror.ErrLoginInvalidCredentials)
	}
}
