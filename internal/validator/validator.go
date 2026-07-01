// Package validator validates handler inputs and converts failures into
// apperror.CodeInvalidArgument errors.
package validator

import (
	"github.com/kurnhyalcantara/kingler/pkg/apperror"
	platvalidator "github.com/kurnhyalcantara/kingler/pkg/platform/validator"

	"github.com/kurnhyalcantara/araquanid/internal/handler/dto"
)

type Validator struct {
	v *platvalidator.Validator
}

func New(v *platvalidator.Validator) *Validator {
	return &Validator{v: v}
}

func (val *Validator) CreateExample(in dto.CreateExampleInput) error { return val.check(in) }
func (val *Validator) GetExample(in dto.GetExampleInput) error       { return val.check(in) }
func (val *Validator) ListExamples(in dto.ListExamplesInput) error   { return val.check(in) }
func (val *Validator) UpdateExample(in dto.UpdateExampleInput) error { return val.check(in) }
func (val *Validator) DeleteExample(in dto.DeleteExampleInput) error { return val.check(in) }

func (val *Validator) check(in any) error {
	if err := val.v.Struct(in); err != nil {
		return apperror.Invalid(err.Error())
	}
	return nil
}
