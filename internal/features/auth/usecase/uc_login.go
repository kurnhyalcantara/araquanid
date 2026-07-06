package usecase

import (
	"context"

	domain_auth "github.com/kurnhyalcantara/araquanid/internal/domain/auth"
	"github.com/kurnhyalcantara/kingler/pkg/apperror"
)

func (u *authUsecase) Login(ctx context.Context, in domain_auth.LoginInput) (*domain_auth.LoginResult, error) {
	// TODO(FR-LOGIN-002..012, FR-POST-AUTH-*): rate-limit (FR-LOGIN-008),
	// resolve the identifier via the Identity ACL (FR-LOGIN-002), enforce the
	// identity status and lockout pre-checks (FR-LOGIN-003/004), verify the
	// password with a timing-consistent dummy hash on miss (FR-LOGIN-005/007),
	// evaluate the force-change / expiry / MFA decision tree (FR-LOGIN-006),
	// and persist the LoginAttempt (FR-POST-AUTH-001).
	return nil, apperror.New(apperror.CodeInternal, "login not implemented")
}
