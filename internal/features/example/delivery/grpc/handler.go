// Package grpc is the gRPC inbound adapter for the example feature. It
// validates requests, maps them to dtos, delegates to the usecase, and maps
// results back to transport types. The REST surface is the same handler
// reached through the grpc-gateway (see the sibling delivery/rest package).
package grpc

import (
	"context"

	examplev1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/example/v1"

	"github.com/kurnhyalcantara/araquanid/internal/features/example/delivery/grpc/dto"
	"github.com/kurnhyalcantara/araquanid/internal/features/example/delivery/grpc/mapper"
	"github.com/kurnhyalcantara/araquanid/internal/features/example/usecase"
	"github.com/kurnhyalcantara/araquanid/internal/validator"
)

type Handler struct {
	examplev1.UnimplementedExampleServiceServer

	usecase   usecase.Usecase
	validator *validator.Validator
}

func NewHandler(uc usecase.Usecase, val *validator.Validator) *Handler {
	return &Handler{usecase: uc, validator: val}
}

func (h *Handler) CreateExample(ctx context.Context, req *examplev1.CreateExampleRequest) (*examplev1.CreateExampleResponse, error) {
	in := mapper.ToCreateExampleInput(req)
	if err := h.validator.CreateExample(in); err != nil {
		return nil, err
	}

	e, err := h.usecase.Create(ctx, in.Name, in.Description)
	if err != nil {
		return nil, err
	}
	return mapper.ToCreateExampleResponse(e), nil
}

func (h *Handler) GetExample(ctx context.Context, req *examplev1.GetExampleRequest) (*examplev1.GetExampleResponse, error) {
	in := dto.GetExampleInput{ID: req.GetId()}
	if err := h.validator.GetExample(in); err != nil {
		return nil, err
	}

	e, err := h.usecase.Get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	return mapper.ToGetExampleResponse(e), nil
}

func (h *Handler) ListExamples(ctx context.Context, req *examplev1.ListExamplesRequest) (*examplev1.ListExamplesResponse, error) {
	in := mapper.ToListExamplesInput(req)
	if err := h.validator.ListExamples(in); err != nil {
		return nil, err
	}

	list, err := h.usecase.List(ctx, in.PageSize, in.PageToken)
	if err != nil {
		return nil, err
	}
	return mapper.ToListExamplesResponse(list), nil
}

func (h *Handler) UpdateExample(ctx context.Context, req *examplev1.UpdateExampleRequest) (*examplev1.UpdateExampleResponse, error) {
	in := mapper.ToUpdateExampleInput(req)
	if err := h.validator.UpdateExample(in); err != nil {
		return nil, err
	}

	e, err := h.usecase.Update(ctx, in.ID, in.Name, in.Description)
	if err != nil {
		return nil, err
	}
	return mapper.ToUpdateExampleResponse(e), nil
}

func (h *Handler) DeleteExample(ctx context.Context, req *examplev1.DeleteExampleRequest) (*examplev1.DeleteExampleResponse, error) {
	in := dto.DeleteExampleInput{ID: req.GetId()}
	if err := h.validator.DeleteExample(in); err != nil {
		return nil, err
	}

	if err := h.usecase.Delete(ctx, in.ID); err != nil {
		return nil, err
	}
	return &examplev1.DeleteExampleResponse{}, nil
}
