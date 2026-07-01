// Package usecase implements the application logic. It depends only on the
// domain, the repository port, and shared packages — never on transport
// (gen/) or infrastructure drivers.
package usecase

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/kurnhyalcantara/kingler/pkg/apperror"
	"github.com/kurnhyalcantara/kingler/pkg/pagination"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/example/repository"
)

// ExampleList is the result of a List call: a page of examples plus the token
// for the next page and the total count.
type ExampleList struct {
	Examples      []*domain.Example
	NextPageToken string
	TotalSize     int64
}

type Usecase interface {
	Create(ctx context.Context, name, description string) (*domain.Example, error)
	Get(ctx context.Context, id string) (*domain.Example, error)
	List(ctx context.Context, pageSize int, pageToken string) (*ExampleList, error)
	Update(ctx context.Context, id, name, description string) (*domain.Example, error)
	Delete(ctx context.Context, id string) error
}

type exampleUsecase struct {
	repo repository.Repository
	now  func() time.Time
}

func New(repo repository.Repository) Usecase {
	return &exampleUsecase{repo: repo, now: time.Now}
}

func (u *exampleUsecase) Create(ctx context.Context, name, description string) (*domain.Example, error) {
	now := u.now()
	e := &domain.Example{
		ID:          uuid.NewString(),
		Name:        name,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := u.repo.Create(ctx, e); err != nil {
		return nil, apperror.Internal(err)
	}
	return e, nil
}

func (u *exampleUsecase) Get(ctx context.Context, id string) (*domain.Example, error) {
	e, err := u.repo.GetByID(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return e, nil
}

func (u *exampleUsecase) List(ctx context.Context, pageSize int, pageToken string) (*ExampleList, error) {
	offset, err := decodePageToken(pageToken)
	if err != nil {
		return nil, apperror.Invalid("invalid page token")
	}
	page := pagination.Normalize(pageSize, offset)

	examples, total, err := u.repo.List(ctx, page.Limit, page.Offset)
	if err != nil {
		return nil, apperror.Internal(err)
	}

	var next string
	if int64(page.Offset+len(examples)) < total {
		next = encodePageToken(page.Offset + page.Limit)
	}
	return &ExampleList{Examples: examples, NextPageToken: next, TotalSize: total}, nil
}

func (u *exampleUsecase) Update(ctx context.Context, id, name, description string) (*domain.Example, error) {
	e, err := u.repo.GetByID(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	e.Update(name, description, u.now())
	if err := u.repo.Update(ctx, e); err != nil {
		return nil, mapNotFound(err)
	}
	return e, nil
}

func (u *exampleUsecase) Delete(ctx context.Context, id string) error {
	if err := u.repo.Delete(ctx, id); err != nil {
		return mapNotFound(err)
	}
	return nil
}

func mapNotFound(err error) error {
	if errors.Is(err, domain.ErrNotFound) {
		return apperror.NotFound("example not found")
	}
	return apperror.Internal(err)
}

// Page tokens are a simple opaque encoding of the list offset. A production
// service may swap this for a cursor over a stable sort key.
func encodePageToken(offset int) string { return strconv.Itoa(offset) }

func decodePageToken(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(token)
	if err != nil || offset < 0 {
		return 0, errors.New("invalid page token")
	}
	return offset, nil
}
