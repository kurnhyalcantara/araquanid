package validator

import "github.com/kurnhyalcantara/araquanid/internal/features/login/delivery/grpc/dto"

func (val *Validator) Login(in dto.LoginInput) error { return val.check(in) }
