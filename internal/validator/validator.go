// Package validator validates handler inputs and converts failures into
// apperror.ErrRequestValidation errors (araquanid's own PRD §13 catalog, not
// kingler's generic one — see internal/apperror). It is shared across all
// features: this file holds the generic engine; per-feature validation
// methods live in their own file (e.g. login.go).
package validator

import (
	platvalidator "github.com/kurnhyalcantara/kingler/pkg/platform/validator"

	"github.com/kurnhyalcantara/araquanid/internal/apperror"
)

type Validator struct {
	v *platvalidator.Validator
}

func New(v *platvalidator.Validator) *Validator {
	return &Validator{v: v}
}

func (val *Validator) check(in any) error {
	if err := val.v.Struct(in); err != nil {
		return apperror.New(apperror.ErrRequestValidation, err.Error())
	}
	return nil
}
