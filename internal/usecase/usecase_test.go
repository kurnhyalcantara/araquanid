package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kurnhyalcantara/kingler/pkg/apperror"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
)

// fakeRepo is an in-memory Repository double preserving insertion order.
type fakeRepo struct {
	byID  map[string]*domain.Example
	order []string
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{byID: map[string]*domain.Example{}}
}

func (r *fakeRepo) Create(_ context.Context, e *domain.Example) error {
	cp := *e
	r.byID[e.ID] = &cp
	r.order = append(r.order, e.ID)
	return nil
}

func (r *fakeRepo) GetByID(_ context.Context, id string) (*domain.Example, error) {
	e, ok := r.byID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *e
	return &cp, nil
}

func (r *fakeRepo) List(_ context.Context, limit, offset int) ([]*domain.Example, int64, error) {
	total := int64(len(r.order))
	out := []*domain.Example{}
	for i := offset; i < len(r.order) && len(out) < limit; i++ {
		cp := *r.byID[r.order[i]]
		out = append(out, &cp)
	}
	return out, total, nil
}

func (r *fakeRepo) Update(_ context.Context, e *domain.Example) error {
	if _, ok := r.byID[e.ID]; !ok {
		return domain.ErrNotFound
	}
	cp := *e
	r.byID[e.ID] = &cp
	return nil
}

func (r *fakeRepo) Delete(_ context.Context, id string) error {
	if _, ok := r.byID[id]; !ok {
		return domain.ErrNotFound
	}
	delete(r.byID, id)
	for i, oid := range r.order {
		if oid == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	return nil
}

var testNow = time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)

func newTestUsecase(repo *fakeRepo) *exampleUsecase {
	uc := New(repo).(*exampleUsecase)
	uc.now = func() time.Time { return testNow }
	return uc
}

func assertCode(t *testing.T, err error, want apperror.Code) {
	t.Helper()
	appErr, ok := errors.AsType[*apperror.Error](err)
	if !ok {
		t.Fatalf("expected *apperror.Error, got %v", err)
	}
	if appErr.Code != want {
		t.Fatalf("expected code %s, got %s (%v)", want, appErr.Code, err)
	}
}

func TestCreatePersists(t *testing.T) {
	repo := newFakeRepo()
	uc := newTestUsecase(repo)

	e, err := uc.Create(context.Background(), "foo", "bar")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if e.ID == "" {
		t.Fatal("expected generated id")
	}
	if !e.CreatedAt.Equal(testNow) || !e.UpdatedAt.Equal(testNow) {
		t.Fatalf("timestamps not stamped: %+v", e)
	}

	stored, err := repo.GetByID(context.Background(), e.ID)
	if err != nil {
		t.Fatalf("example not persisted: %v", err)
	}
	if stored.Name != "foo" || stored.Description != "bar" {
		t.Fatalf("unexpected stored example: %+v", stored)
	}
}

func TestGetNotFound(t *testing.T) {
	uc := newTestUsecase(newFakeRepo())

	_, err := uc.Get(context.Background(), "00000000-0000-4000-8000-000000000000")
	if err == nil {
		t.Fatal("expected not found")
	}
	assertCode(t, err, apperror.CodeNotFound)
}

func TestUpdateMutates(t *testing.T) {
	repo := newFakeRepo()
	uc := newTestUsecase(repo)

	created, _ := uc.Create(context.Background(), "foo", "bar")

	updated, err := uc.Update(context.Background(), created.ID, "foo2", "bar2")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "foo2" || updated.Description != "bar2" {
		t.Fatalf("update not applied: %+v", updated)
	}

	if _, err := uc.Update(context.Background(), "00000000-0000-4000-8000-000000000000", "x", "y"); err == nil {
		t.Fatal("expected not found for missing example")
	} else {
		assertCode(t, err, apperror.CodeNotFound)
	}
}

func TestDeleteIsNotFoundAfterRemoval(t *testing.T) {
	repo := newFakeRepo()
	uc := newTestUsecase(repo)

	created, _ := uc.Create(context.Background(), "foo", "bar")

	if err := uc.Delete(context.Background(), created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := uc.Delete(context.Background(), created.ID); err == nil {
		t.Fatal("expected not found deleting twice")
	} else {
		assertCode(t, err, apperror.CodeNotFound)
	}
}

func TestListPaginates(t *testing.T) {
	repo := newFakeRepo()
	uc := newTestUsecase(repo)

	for range 3 {
		if _, err := uc.Create(context.Background(), "name", "desc"); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	first, err := uc.List(context.Background(), 2, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(first.Examples) != 2 {
		t.Fatalf("page size = %d, want 2", len(first.Examples))
	}
	if first.TotalSize != 3 {
		t.Fatalf("total = %d, want 3", first.TotalSize)
	}
	if first.NextPageToken == "" {
		t.Fatal("expected a next page token")
	}

	second, err := uc.List(context.Background(), 2, first.NextPageToken)
	if err != nil {
		t.Fatalf("List page 2: %v", err)
	}
	if len(second.Examples) != 1 {
		t.Fatalf("page 2 size = %d, want 1", len(second.Examples))
	}
	if second.NextPageToken != "" {
		t.Fatal("expected no further pages")
	}
}

func TestListRejectsBadToken(t *testing.T) {
	uc := newTestUsecase(newFakeRepo())

	_, err := uc.List(context.Background(), 10, "not-a-number")
	if err == nil {
		t.Fatal("expected error for bad page token")
	}
	assertCode(t, err, apperror.CodeInvalidArgument)
}
