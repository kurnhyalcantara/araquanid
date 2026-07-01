package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/auth/repository"
)

// errNotImplemented marks repository methods whose queries are scaffolded but
// whose logic is deferred (the usecase short-circuits before reaching them).
var errNotImplemented = errors.New("auth repository: not implemented")

type mfaRepository struct {
	pool *pgxpool.Pool
}

// NewMFARepository returns the PostgreSQL-backed MFA repository (mfa_factors,
// mfa_pending_otps, mfa_recovery_codes).
func NewMFARepository(pool *pgxpool.Pool) repository.MFARepository {
	return &mfaRepository{pool: pool}
}

func (r *mfaRepository) ListActiveFactors(ctx context.Context, identityID string) ([]*domain.MFAFactor, error) {
	// TODO(FR-MFA-VERIFY-002): SELECT active factors for identity_id.
	return nil, errNotImplemented
}

func (r *mfaRepository) GetFactorByCredentialID(ctx context.Context, identityID string, credentialID []byte) (*domain.MFAFactor, error) {
	// TODO(FR-MFA-VERIFY-004): SELECT FIDO2 factor by fido2_credential_id.
	return nil, errNotImplemented
}

func (r *mfaRepository) UpdateFactor(ctx context.Context, f *domain.MFAFactor) error {
	// TODO(FR-MFA-VERIFY-002/004): UPDATE last_used_at/last_used_window/fido2_counter.
	return errNotImplemented
}

func (r *mfaRepository) GetPendingOTP(ctx context.Context, identityID, purpose string) (*domain.MFAPendingOTP, error) {
	// TODO(FR-MFA-VERIFY-003): SELECT unused, unexpired OTP for identity/purpose.
	return nil, errNotImplemented
}

func (r *mfaRepository) UpdatePendingOTP(ctx context.Context, o *domain.MFAPendingOTP) error {
	// TODO(FR-MFA-VERIFY-003): UPDATE attempt_count/is_used/used_at.
	return errNotImplemented
}

func (r *mfaRepository) ListRecoveryCodes(ctx context.Context, identityID string) ([]*domain.MFARecoveryCode, error) {
	// TODO(FR-MFA-VERIFY-005): SELECT unused recovery codes for identity.
	return nil, errNotImplemented
}

func (r *mfaRepository) MarkRecoveryCodeUsed(ctx context.Context, id string) error {
	// TODO(FR-MFA-VERIFY-005): UPDATE is_used = true, used_at = now().
	return errNotImplemented
}
