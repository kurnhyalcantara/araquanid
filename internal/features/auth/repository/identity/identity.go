// Package identity is the anti-corruption adapter over the Identity bounded
// context. It implements the auth feature's IdentityACL port by calling the
// probopass identity/v1 gRPC service and translating its wire types into the
// auth domain's IdentityRef, so the Identity Context's model never leaks into
// the auth module. Importing the generated stubs here is intentional: this is a
// repository adapter to an external gRPC service (see docs/ARCHITECTURE.md).
package identity

import (
	"context"
	"errors"
	"fmt"

	identityv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/identity/v1"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/auth/repository"
)

// ErrUnavailable is returned when the ACL has no configured Identity Context
// client to dial.
var ErrUnavailable = errors.New("auth repository: identity context unavailable")

type identityACL struct {
	client identityv1.IdentityServiceClient
}

// NewACL returns the Identity Context anti-corruption adapter. A nil client
// leaves the ACL unconfigured; calls then fail with ErrUnavailable (the
// Identity Context is dialed once its endpoint is provisioned).
func NewACL(client identityv1.IdentityServiceClient) repository.IdentityACL {
	return &identityACL{client: client}
}

func (a *identityACL) Resolve(ctx context.Context, identifier string) (*domain.IdentityRef, bool, error) {
	if a.client == nil {
		return nil, false, ErrUnavailable
	}
	resp, err := a.client.ResolveIdentity(ctx, &identityv1.ResolveIdentityRequest{Identifier: identifier})
	if err != nil {
		return nil, false, fmt.Errorf("auth repository: resolve identity: %w", err)
	}
	if !resp.GetFound() {
		return nil, false, nil
	}
	return &domain.IdentityRef{
		IdentityID:  resp.GetIdentityId(),
		Status:      identityStatus(resp.GetStatus()),
		CorporateID: resp.GetCorporateId(),
	}, true, nil
}

func (a *identityACL) Get(ctx context.Context, identityID string) (*domain.IdentityRef, error) {
	if a.client == nil {
		return nil, ErrUnavailable
	}
	resp, err := a.client.GetIdentity(ctx, &identityv1.GetIdentityRequest{IdentityId: identityID})
	if err != nil {
		return nil, fmt.Errorf("auth repository: get identity: %w", err)
	}
	return &domain.IdentityRef{
		IdentityID:  resp.GetIdentityId(),
		Username:    resp.GetUsername(),
		DisplayName: resp.GetDisplayName(),
		Status:      identityStatus(resp.GetStatus()),
		CorporateID: resp.GetCorporateId(),
		MaskedPhone: resp.GetMaskedPhone(),
	}, nil
}

// identityStatus maps the wire enum into the auth domain's status.
func identityStatus(s identityv1.IdentityStatus) domain.IdentityStatus {
	switch s {
	case identityv1.IdentityStatus_IDENTITY_STATUS_ACTIVE:
		return domain.IdentityActive
	case identityv1.IdentityStatus_IDENTITY_STATUS_INACTIVE:
		return domain.IdentityInactive
	case identityv1.IdentityStatus_IDENTITY_STATUS_SUSPENDED:
		return domain.IdentitySuspended
	case identityv1.IdentityStatus_IDENTITY_STATUS_PENDING_ACTIVATION:
		return domain.IdentityPendingActivation
	case identityv1.IdentityStatus_IDENTITY_STATUS_DELETED:
		return domain.IdentityDeleted
	default:
		return ""
	}
}
