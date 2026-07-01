package validator

import (
	"github.com/kurnhyalcantara/araquanid/internal/features/example/delivery/grpc/dto"
)

func (val *Validator) CreateExample(in dto.CreateExampleInput) error { return val.check(in) }
func (val *Validator) GetExample(in dto.GetExampleInput) error       { return val.check(in) }
func (val *Validator) ListExamples(in dto.ListExamplesInput) error   { return val.check(in) }
func (val *Validator) UpdateExample(in dto.UpdateExampleInput) error { return val.check(in) }
func (val *Validator) DeleteExample(in dto.DeleteExampleInput) error { return val.check(in) }
