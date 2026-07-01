package mapper

import (
	"testing"
	"time"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/example/usecase"
)

func TestToProtoExample(t *testing.T) {
	created := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	updated := created.Add(time.Hour)

	e := &domain.Example{
		ID:          "id",
		Name:        "name",
		Description: "desc",
		CreatedAt:   created,
		UpdatedAt:   updated,
	}

	pb := ToProtoExample(e)
	if pb.GetId() != e.ID || pb.GetName() != e.Name || pb.GetDescription() != e.Description {
		t.Fatalf("fields not mapped: %+v", pb)
	}
	if !pb.GetCreatedAt().AsTime().Equal(created) {
		t.Fatalf("created_at = %v, want %v", pb.GetCreatedAt().AsTime(), created)
	}
	if !pb.GetUpdatedAt().AsTime().Equal(updated) {
		t.Fatalf("updated_at = %v, want %v", pb.GetUpdatedAt().AsTime(), updated)
	}
}

func TestToProtoExampleNilSafety(t *testing.T) {
	if ToProtoExample(nil) != nil {
		t.Fatal("nil example must map to nil")
	}
}

func TestToListExamplesResponse(t *testing.T) {
	list := &usecase.ExampleList{
		Examples:      []*domain.Example{{ID: "a"}, {ID: "b"}},
		NextPageToken: "2",
		TotalSize:     5,
	}
	resp := ToListExamplesResponse(list)
	if len(resp.GetExamples()) != 2 {
		t.Fatalf("examples count = %d, want 2", len(resp.GetExamples()))
	}
	if resp.GetPage().GetNextPageToken() != "2" || resp.GetPage().GetTotalSize() != 5 {
		t.Fatalf("page metadata not mapped: %+v", resp.GetPage())
	}
}
