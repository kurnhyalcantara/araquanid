// Package dto defines the handler's request input structures, carrying the
// validation rules applied before requests reach the usecase.
package dto

type CreateExampleInput struct {
	Name        string `validate:"required,max=128"`
	Description string `validate:"max=1024"`
}

type GetExampleInput struct {
	ID string `validate:"required,uuid4"`
}

type ListExamplesInput struct {
	PageSize  int    `validate:"gte=0,lte=100"`
	PageToken string `validate:"max=64"`
}

type UpdateExampleInput struct {
	ID          string `validate:"required,uuid4"`
	Name        string `validate:"required,max=128"`
	Description string `validate:"max=1024"`
}

type DeleteExampleInput struct {
	ID string `validate:"required,uuid4"`
}
