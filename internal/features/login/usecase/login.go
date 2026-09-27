package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/kurnhyalcantara/araquanid/internal/apperror"
	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
	"github.com/kurnhyalcantara/araquanid/internal/platform/jwtsign"
	"github.com/kurnhyalcantara/araquanid/internal/platform/passwordhash"
)

// maxPasswordLen is BR-001's server-side truncation length.
const maxPasswordLen = 128

// Login implements FR-LOGIN-001..012 for POST /api/v1/auth/login (the
// mesh-authenticated endpoint split and VerifyMfa are out of this feature's
// scope — see the plan's Context section).
func (u *Usecase) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	cfg := u.deps.Config
	now := u.deps.Clock().UTC()

	identifierHash := sha256Hex(in.Identifier)
	password := truncate(in.Password, maxPasswordLen) // BR-001, before anything else

	// FR-LOGIN-008: rate limit before any DB operation.
	if rlErr, err := u.checkRateLimit(ctx, ipString(in.IP), identifierHash); err != nil {
		return nil, err
	} else if rlErr != nil {
		u.recordAttemptBestEffort(ctx, repository.LoginAttemptRecord{
			IdentifierHash: identifierHash,
			Outcome:        "RATE_LIMITED",
			IPAddress:      ipString(in.IP),
			UserAgent:      in.UserAgent,
			AttemptedAt:    now,
		})
		return nil, rlErr
	}

	identifier := normalize(in.Identifier) // BR-002
	companyCode := strings.ToUpper(strings.TrimSpace(in.CompanyCode))
	fingerprintHash := computeFingerprint(in.UserAgent, in.AcceptLanguage, in.DeviceFingerprint, in.IP)

	// FR-LOGIN-002/003: resolve identifier, only ACTIVE identities proceed.
	resolved, found, err := u.deps.IdentityACL.ResolveIdentity(ctx, identifier, companyCode)
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemUpstream, "resolve identity", err)
	}
	if !found || resolved.Status != "ACTIVE" {
		return u.invalidCredentials(ctx, nil, identifierHash, fingerprintHash, password, in, now)
	}

	cred, err := u.deps.Credentials.FindByIdentity(ctx, resolved.IdentityID)
	if errors.Is(err, domain.ErrCredentialNotFound) {
		return u.invalidCredentials(ctx, &resolved.IdentityID, identifierHash, fingerprintHash, password, in, now)
	}
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemDatabase, "load credential", err)
	}

	// FR-LOGIN-004: lockout pre-check (also auto-lifts an elapsed temporary
	// lock in place, without recording it until we persist below).
	if err := cred.EnsureVerifiable(now); err != nil {
		u.recordAttemptBestEffort(ctx, repository.LoginAttemptRecord{
			IdentityID:        &resolved.IdentityID,
			IdentifierHash:    identifierHash,
			Outcome:           "LOCKED",
			IPAddress:         ipString(in.IP),
			UserAgent:         in.UserAgent,
			DeviceFingerprint: fingerprintHash,
			AttemptedAt:       now,
		})
		appErr := apperror.New(apperror.ErrLoginAccountLocked, "account is locked")
		if until := cred.LockedUntil(); until != nil {
			appErr = appErr.WithDetail("locked_until", until.Format(time.RFC3339))
		}
		return nil, appErr
	}

	// FR-LOGIN-005: password verification.
	attempt := domain.AttemptContext{
		CompanyCode:       companyCode,
		IP:                in.IP,
		UserAgent:         in.UserAgent,
		DeviceFingerprint: fingerprintHash,
	}
	if !verifyPassword(password, cred, cfg.Argon2id) {
		return u.failCredential(ctx, cred, attempt, resolved.IdentityID, identifierHash, fingerprintHash, in, now)
	}

	// FR-LOGIN-005 (success): reset the consecutive-failure counter.
	if err := cred.RecordSuccessfulVerification(now); err != nil {
		// Unreachable in practice: EnsureVerifiable was just checked above
		// and nothing else mutates cred concurrently within one request.
		return nil, apperror.Wrap(apperror.ErrSystemInternal, "record successful verification", err)
	}

	// FR-DEVICE-002 read (must happen before the BR-003 MFA decision).
	device, err := u.deps.Devices.FindByFingerprint(ctx, resolved.IdentityID, fingerprintHash)
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemDatabase, "find device", err)
	}

	// BR-003: corporate-policy and Bank-Administrator/risk-score conditions
	// are stubbed false — no Corporate Context or risk-scoring engine exists
	// anywhere in this codebase yet (see the plan's Context section).
	hasActiveFactor, err := u.deps.MFAFactors.HasActiveFactor(ctx, resolved.IdentityID)
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemDatabase, "check active mfa factor", err)
	}
	mfaRequired := hasActiveFactor || device == nil

	// FR-LOGIN-006 decision tree.
	switch {
	case cred.ForcePasswordChange() || cred.IsPasswordExpired(now):
		return u.completeForcedChange(ctx, cred, resolved.IdentityID, identifierHash, fingerprintHash, in, now)
	case mfaRequired:
		return u.completeMFARequired(ctx, cred, resolved.IdentityID, identifierHash, fingerprintHash, in, now)
	default:
		return u.completeSession(ctx, cred, resolved, device, identifierHash, fingerprintHash, in, now)
	}
}

// invalidCredentials handles both the identity-not-found/inactive and
// credential-not-found paths identically (FR-LOGIN-002/003/007): a dummy
// Argon2id computation keeps response timing indistinguishable from a real
// wrong-password check, and the externally-visible outcome is always
// ErrLoginInvalidCredentials — a distinct ERR-LOGIN-002 would leak identity
// existence, which FR-LOGIN-003 explicitly forbids.
func (u *Usecase) invalidCredentials(ctx context.Context, identityID *string, identifierHash, fingerprintHash, password string, in LoginInput, now time.Time) (*LoginResult, error) {
	passwordhash.DummyVerify(password, u.deps.Config.Argon2id)
	u.recordAttemptBestEffort(ctx, repository.LoginAttemptRecord{
		IdentityID:        identityID,
		IdentifierHash:    identifierHash,
		Outcome:           "FAILED_CREDENTIALS",
		IPAddress:         ipString(in.IP),
		UserAgent:         in.UserAgent,
		DeviceFingerprint: fingerprintHash,
		AttemptedAt:       now,
	})
	return nil, apperror.New(apperror.ErrLoginInvalidCredentials, "invalid credentials")
}

// failCredential handles FR-LOGIN-007: a wrong password against a real,
// verifiable credential.
func (u *Usecase) failCredential(ctx context.Context, cred *domain.Credential, attempt domain.AttemptContext, identityID, identifierHash, fingerprintHash string, in LoginInput, now time.Time) (*LoginResult, error) {
	_ = cred.RecordFailedAttempt(attempt, u.deps.Config.Lockout, now) // see doc comment on the unreachable-error case above
	events := cred.PullEvents()

	err := u.deps.UnitOfWork.Execute(ctx, func(ctx context.Context, r repository.TxRepositories) error {
		if err := r.Credentials.Save(ctx, cred); err != nil {
			return err
		}
		if err := r.Outbox.Append(ctx, events); err != nil {
			return err
		}
		return r.LoginAttempts.Record(ctx, repository.LoginAttemptRecord{
			IdentityID:        &identityID,
			IdentifierHash:    identifierHash,
			Outcome:           "FAILED_CREDENTIALS",
			IPAddress:         ipString(in.IP),
			UserAgent:         in.UserAgent,
			DeviceFingerprint: fingerprintHash,
			AttemptedAt:       now,
		})
	})
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemDatabase, "persist failed login attempt", err)
	}
	return nil, apperror.New(apperror.ErrLoginInvalidCredentials, "invalid credentials")
}

// completeForcedChange handles FR-LOGIN-006 steps 1-2: a forced or expired
// password takes priority over an MFA requirement (BR-011).
func (u *Usecase) completeForcedChange(ctx context.Context, cred *domain.Credential, identityID, identifierHash, fingerprintHash string, in LoginInput, now time.Time) (*LoginResult, error) {
	token, err := u.deps.TokenSigner.SignRestrictedToken(identityID, "password_change", u.deps.Config.ForcedChangeWindow)
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemInternal, "sign restricted token", err)
	}
	events := cred.PullEvents()

	err = u.deps.UnitOfWork.Execute(ctx, func(ctx context.Context, r repository.TxRepositories) error {
		if err := r.Credentials.Save(ctx, cred); err != nil {
			return err
		}
		if err := r.Outbox.Append(ctx, events); err != nil {
			return err
		}
		return r.LoginAttempts.Record(ctx, repository.LoginAttemptRecord{
			IdentityID:        &identityID,
			IdentifierHash:    identifierHash,
			Outcome:           "PASSWORD_CHANGE_REQUIRED",
			IPAddress:         ipString(in.IP),
			UserAgent:         in.UserAgent,
			DeviceFingerprint: fingerprintHash,
			AttemptedAt:       now,
		})
	})
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemDatabase, "persist password-change-required outcome", err)
	}

	return &LoginResult{
		AuthenticationResult:     "PASSWORD_CHANGE_REQUIRED",
		ForcePasswordChange:      true,
		ForcedChangeSessionToken: token,
	}, nil
}

// completeMFARequired handles FR-LOGIN-006 step 3 / FR-LOGIN-010: credential
// verified, a second factor is still required. The MFA session state is
// created only after the DB transaction below commits, so a Redis write
// never precedes the durable record of this outcome.
func (u *Usecase) completeMFARequired(ctx context.Context, cred *domain.Credential, identityID, identifierHash, fingerprintHash string, in LoginInput, now time.Time) (*LoginResult, error) {
	factors, err := u.deps.MFAFactors.ListActiveFactorTypes(ctx, identityID)
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemDatabase, "list active mfa factors", err)
	}
	token, err := randomOpaqueToken()
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemInternal, "generate mfa session token", err)
	}
	events := cred.PullEvents()

	err = u.deps.UnitOfWork.Execute(ctx, func(ctx context.Context, r repository.TxRepositories) error {
		if err := r.Credentials.Save(ctx, cred); err != nil {
			return err
		}
		if err := r.Outbox.Append(ctx, events); err != nil {
			return err
		}
		return r.LoginAttempts.Record(ctx, repository.LoginAttemptRecord{
			IdentityID:        &identityID,
			IdentifierHash:    identifierHash,
			Outcome:           "MFA_REQUIRED",
			IPAddress:         ipString(in.IP),
			UserAgent:         in.UserAgent,
			DeviceFingerprint: fingerprintHash,
			AttemptedAt:       now,
		})
	})
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemDatabase, "persist mfa-required outcome", err)
	}

	if err := u.deps.MFASessionStore.Create(ctx, token, repository.MFASessionState{
		IdentityID:           identityID,
		CredentialVerifiedAt: now,
		AvailableFactors:     factors,
		ClientID:             in.ClientID,
		DeviceFingerprint:    fingerprintHash,
	}, u.deps.Config.MFASessionWindow); err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemUpstream, "create mfa session", err)
	}

	return &LoginResult{
		AuthenticationResult: "MFA_REQUIRED",
		MFASessionToken:      token,
		AvailableFactors:     factors,
	}, nil
}

// completeSession handles FR-LOGIN-006 step 4 / FR-SESSION-001..003 /
// FR-LOGIN-012: no MFA needed, create the session, issue tokens, apply the
// concurrent-session policy and the device write, all in one transaction.
func (u *Usecase) completeSession(ctx context.Context, cred *domain.Credential, resolved *repository.ResolvedIdentity, device *repository.RegisteredDevice, identifierHash, fingerprintHash string, in LoginInput, now time.Time) (*LoginResult, error) {
	cfg := u.deps.Config
	sessionID := u.deps.NewID()

	// Login's own reachable path only ever produces AAL1 (password-only,
	// no factors used) — an MFA-verified session (AAL2/AAL3) is created by
	// the separate, out-of-scope VerifyMfa feature.
	session, err := domain.NewAuthenticationSession(domain.NewSessionParams{
		ID:       domain.SessionID(sessionID),
		Identity: domain.IdentityRef(resolved.IdentityID),
		AAL:      domain.AAL1,
		Client:   domain.ClientInfo{IP: in.IP, UserAgent: in.UserAgent},
		Policy:   cfg.SessionPolicy,
		Now:      now,
	})
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemInternal, "create session", err)
	}

	rawRefreshToken, err := randomOpaqueToken()
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemInternal, "generate refresh token", err)
	}
	familyID := u.deps.NewID()

	accessToken, err := u.deps.TokenSigner.SignAccessToken(jwtsign.AccessTokenClaims{
		Subject:     resolved.IdentityID,
		Audience:    []string{in.ClientID},
		SessionID:   sessionID,
		AAL:         string(domain.AAL1),
		CorporateID: resolved.CorporateID,
	}, cfg.AccessTokenTTL)
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemInternal, "sign access token", err)
	}

	credEvents := cred.PullEvents()

	err = u.deps.UnitOfWork.Execute(ctx, func(ctx context.Context, r repository.TxRepositories) error {
		if err := applyConcurrentSessionPolicy(ctx, r.Sessions, resolved.IdentityID, in.ClientID, cfg, now); err != nil {
			return err
		}

		var deviceID string
		if device != nil {
			deviceID = device.ID
			if err := r.Devices.Touch(ctx, device.ID, now); err != nil {
				return err
			}
		} else {
			newID, err := r.Devices.Register(ctx, resolved.IdentityID, fingerprintHash, cfg.FingerprintVersion,
				inferDeviceName(in.UserAgent), ipString(in.IP), now)
			if err != nil {
				return err
			}
			deviceID = newID
		}
		_ = deviceID // device_id lives on the session row via session.Device(), not tracked further here

		if err := r.Credentials.Save(ctx, cred); err != nil {
			return err
		}
		if err := r.Sessions.Create(ctx, session, in.ClientID); err != nil {
			return err
		}
		if err := r.RefreshTokens.CreateFamily(ctx, familyID, sessionID, resolved.IdentityID); err != nil {
			return err
		}
		if err := r.RefreshTokens.CreateToken(ctx, repository.RefreshTokenRecord{
			FamilyID:  familyID,
			TokenHash: sha256Hex(rawRefreshToken),
			ClientID:  in.ClientID,
			IssuerIP:  ipString(in.IP),
			IssuedAt:  now,
			ExpiresAt: now.Add(cfg.RefreshTokenTTL),
		}); err != nil {
			return err
		}

		events := append(credEvents, session.PullEvents()...)
		if err := r.Outbox.Append(ctx, events); err != nil {
			return err
		}

		return r.LoginAttempts.Record(ctx, repository.LoginAttemptRecord{
			IdentityID:        &resolved.IdentityID,
			IdentifierHash:    identifierHash,
			Outcome:           "SUCCEEDED",
			IPAddress:         ipString(in.IP),
			UserAgent:         in.UserAgent,
			DeviceFingerprint: fingerprintHash,
			SessionID:         &sessionID,
			AttemptedAt:       now,
		})
	})
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemDatabase, "persist completed login", err)
	}

	return &LoginResult{
		AuthenticationResult: "COMPLETED",
		AccessToken:          accessToken,
		TokenType:            "Bearer",
		ExpiresIn:            int64(cfg.AccessTokenTTL.Seconds()),
		RefreshToken:         rawRefreshToken,
		SessionID:            sessionID,
		AAL:                  string(domain.AAL1),
		ForcePasswordChange:  false,
	}, nil
}

// applyConcurrentSessionPolicy implements FR-LOGIN-012, scoped by identity +
// calling client (the plain client_id request field — see the plan's
// Context section on why this feature does not resolve a mesh-verified
// peer identity).
func applyConcurrentSessionPolicy(ctx context.Context, sessions repository.TxSessions, identityID, clientID string, cfg Config, now time.Time) error {
	switch cfg.ConcurrentPolicy {
	case "SINGLE":
		active, err := sessions.ListActive(ctx, identityID, clientID)
		if err != nil {
			return err
		}
		for _, s := range active {
			if err := s.Revoke(domain.ReasonConcurrentSessionLimit, "", now); err != nil {
				continue // already terminal somehow; nothing to persist for it
			}
			if err := sessions.Revoke(ctx, s); err != nil {
				return err
			}
		}
	case "LIMIT_N":
		count, err := sessions.CountActive(ctx, identityID, clientID)
		if err != nil {
			return err
		}
		if count >= cfg.ConcurrentMax {
			oldest, err := sessions.FindOldestActive(ctx, identityID, clientID)
			if err != nil {
				return err
			}
			if oldest != nil {
				if err := oldest.Revoke(domain.ReasonConcurrentSessionLimit, "", now); err == nil {
					if err := sessions.Revoke(ctx, oldest); err != nil {
						return err
					}
				}
			}
		}
	case "ALLOW_ALL":
		// No action.
	}
	return nil
}

func (u *Usecase) checkRateLimit(ctx context.Context, ip, identifierHash string) (*apperror.Error, error) {
	rl := u.deps.Config.RateLimit

	allowed, retryAfter, err := u.deps.RateLimiter.Allow(ctx, "ratelimit:login:ip:"+ip, rl.IPMaxAttempts, rl.IPWindow)
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemUpstream, "rate limit check", err)
	}
	if !allowed {
		return apperror.RateLimited(retryAfter), nil
	}

	allowed, retryAfter, err = u.deps.RateLimiter.Allow(ctx, "ratelimit:login:identity:"+identifierHash+":"+ip, rl.IdentityMaxAttempts, rl.IdentityWindow)
	if err != nil {
		return nil, apperror.Wrap(apperror.ErrSystemUpstream, "rate limit check", err)
	}
	if !allowed {
		return apperror.RateLimited(retryAfter), nil
	}
	return nil, nil
}

// recordAttemptBestEffort records a login_attempts row outside any
// transaction (the rate-limited and identity/credential-not-found paths
// never enter one). A failure here is logged, not returned — the security
// decision already made must not be masked by an audit-log write failure.
func (u *Usecase) recordAttemptBestEffort(ctx context.Context, rec repository.LoginAttemptRecord) {
	if err := u.deps.LoginAttempts.Record(ctx, rec); err != nil {
		u.deps.Logger.Error("login: failed to record login attempt", slog.String("error", err.Error()))
	}
}

func verifyPassword(password string, cred *domain.Credential, params passwordhash.Argon2idParams) bool {
	ph := cred.Password()
	switch ph.Algorithm() {
	case domain.PasswordArgon2id:
		return passwordhash.Verify(password, ph.Hash(), ph.Salt(), params)
	case domain.PasswordBcrypt:
		return passwordhash.VerifyBcrypt(password, ph.Hash())
	default:
		return false
	}
}

func randomOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func ipString(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}
