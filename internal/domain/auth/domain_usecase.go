package domain_auth

import (
	"context"
)

// Usecase is the auth feature's application-logic port consumed by the handler.
type Usecase interface {
	// Login verifies credentials and returns the next step (completed, MFA
	// required, or password change required) per the FR-LOGIN-006 decision tree.
	Login(ctx context.Context, in LoginInput) (*LoginResult, error)
}
