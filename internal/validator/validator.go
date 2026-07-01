// Package validator validates handler inputs and converts failures into
// apperror.CodeInvalidArgument errors. It is shared across all features:
// this file holds the generic engine; per-feature validation methods live in
// their own file (e.g. example.go).
package validator

import (
	"github.com/kurnhyalcantara/kingler/pkg/apperror"
	platvalidator "github.com/kurnhyalcantara/kingler/pkg/platform/validator"
)

type Validator struct {
	v *platvalidator.Validator
}

func New(v *platvalidator.Validator) *Validator {
	return &Validator{v: v}
}

func (val *Validator) check(in any) error {
	if err := val.v.Struct(in); err != nil {
		return apperror.Invalid(err.Error())
	}
	return nil
}
