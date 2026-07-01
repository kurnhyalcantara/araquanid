package validator

import (
	"github.com/kurnhyalcantara/araquanid/internal/features/auth/delivery/grpc/dto"
)

func (val *Validator) Login(in dto.LoginInput) error         { return val.check(in) }
func (val *Validator) VerifyMFA(in dto.VerifyMFAInput) error { return val.check(in) }
