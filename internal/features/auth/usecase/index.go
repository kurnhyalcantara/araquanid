package usecase

import (
	"time"

	domain_auth "github.com/kurnhyalcantara/araquanid/internal/domain/auth"
)

type authUsecase struct {
	credentials domain_auth.CredentialRepository
	attempts    domain_auth.LoginAttemptRepository
	mfa         domain_auth.MFARepository
	mfaSessions domain_auth.MFASessionStore
	identity    domain_auth.IdentityACL
	cfg         domain_auth.Config
	now         func() time.Time
}

type Dependencies struct {
	CredentialRepository   domain_auth.CredentialRepository
	LoginAttemptRepository domain_auth.LoginAttemptRepository
	MFARepository          domain_auth.MFARepository
	MFASessionStore        domain_auth.MFASessionStore
	IdentityACL            domain_auth.IdentityACL
	Config                 domain_auth.Config
}

// New constructs the auth usecase from its repository ports and configuration.
func New(
	dependencies Dependencies,
) domain_auth.Usecase {
	return &authUsecase{
		credentials: dependencies.CredentialRepository,
		attempts:    dependencies.LoginAttemptRepository,
		mfa:         dependencies.MFARepository,
		mfaSessions: dependencies.MFASessionStore,
		identity:    dependencies.IdentityACL,
		cfg:         dependencies.Config,
		now:         time.Now,
	}
}
