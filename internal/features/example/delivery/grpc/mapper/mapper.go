// Package mapper converts between transport types (the probopass contract),
// handler dtos, and domain/usecase types. Mappers are pure functions;
// transport types must not leak past this package into usecases or the domain.
package mapper

import (
	commonv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/common/v1"
	examplev1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/example/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/example/delivery/grpc/dto"
	"github.com/kurnhyalcantara/araquanid/internal/features/example/usecase"
)

func ToProtoExample(e *domain.Example) *examplev1.Example {
	if e == nil {
		return nil
	}
	return &examplev1.Example{
		Id:          e.ID,
		Name:        e.Name,
		Description: e.Description,
		CreatedAt:   timestamppb.New(e.CreatedAt),
		UpdatedAt:   timestamppb.New(e.UpdatedAt),
	}
}

func ToCreateExampleInput(req *examplev1.CreateExampleRequest) dto.CreateExampleInput {
	return dto.CreateExampleInput{
		Name:        req.GetName(),
		Description: req.GetDescription(),
	}
}

func ToUpdateExampleInput(req *examplev1.UpdateExampleRequest) dto.UpdateExampleInput {
	return dto.UpdateExampleInput{
		ID:          req.GetId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
	}
}

func ToListExamplesInput(req *examplev1.ListExamplesRequest) dto.ListExamplesInput {
	return dto.ListExamplesInput{
		PageSize:  int(req.GetPage().GetPageSize()),
		PageToken: req.GetPage().GetPageToken(),
	}
}

func ToCreateExampleResponse(e *domain.Example) *examplev1.CreateExampleResponse {
	return &examplev1.CreateExampleResponse{Example: ToProtoExample(e)}
}

func ToGetExampleResponse(e *domain.Example) *examplev1.GetExampleResponse {
	return &examplev1.GetExampleResponse{Example: ToProtoExample(e)}
}

func ToUpdateExampleResponse(e *domain.Example) *examplev1.UpdateExampleResponse {
	return &examplev1.UpdateExampleResponse{Example: ToProtoExample(e)}
}

func ToListExamplesResponse(list *usecase.ExampleList) *examplev1.ListExamplesResponse {
	examples := make([]*examplev1.Example, 0, len(list.Examples))
	for _, e := range list.Examples {
		examples = append(examples, ToProtoExample(e))
	}
	return &examplev1.ListExamplesResponse{
		Examples: examples,
		Page: &commonv1.PageResponse{
			NextPageToken: list.NextPageToken,
			TotalSize:     list.TotalSize,
		},
	}
}
