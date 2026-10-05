// Package identity is the anti-corruption-layer adapter over the Identity
// bounded context (a separate microservice; identityv1.IdentityServiceClient
// is its gRPC contract, internal-only per identity.proto).
package identity

import (
	"context"
	"errors"
	"fmt"

	identityv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/identity/v1"

	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
	"github.com/kurnhyalcantara/araquanid/internal/platform/service"
)

// ErrUnavailable is returned when the Identity Context client was never
// configured (config.Identity.Addr empty) — every call fails closed rather
// than silently no-op'ing.
var ErrUnavailable = errors.New("login/identity: identity context unavailable")

type acl struct {
	client service.IdentityClient
}

// NewACL builds a repository.IdentityACL over client. client may be nil (no
// Identity Context endpoint configured); every call then returns
// ErrUnavailable instead of panicking.
func NewACL(client service.IdentityClient) repository.IdentityACL {
	return &acl{client: client}
}

func (a *acl) ResolveIdentity(ctx context.Context, identifier, companyCode string) (*repository.ResolvedIdentity, bool, error) {
	if a.client == nil {
		return nil, false, ErrUnavailable
	}

	resp, err := a.client.ResolveIdentity(ctx, &identityv1.ResolveIdentityRequest{
		Identifier:  identifier,
		CompanyCode: companyCode,
	})
	if err != nil {
		return nil, false, fmt.Errorf("login/identity: resolve identity: %w", err)
	}
	if !resp.GetFound() {
		return nil, false, nil
	}
	return &repository.ResolvedIdentity{
		IdentityID:  resp.GetIdentityId(),
		Status:      identityStatusString(resp.GetStatus()),
		CorporateID: resp.GetCorporateId(),
	}, true, nil
}

func identityStatusString(s identityv1.IdentityStatus) string {
	switch s {
	case identityv1.IdentityStatus_IDENTITY_STATUS_ACTIVE:
		return "ACTIVE"
	case identityv1.IdentityStatus_IDENTITY_STATUS_INACTIVE:
		return "INACTIVE"
	case identityv1.IdentityStatus_IDENTITY_STATUS_SUSPENDED:
		return "SUSPENDED"
	case identityv1.IdentityStatus_IDENTITY_STATUS_PENDING_ACTIVATION:
		return "PENDING_ACTIVATION"
	case identityv1.IdentityStatus_IDENTITY_STATUS_DELETED:
		return "DELETED"
	default:
		return "UNSPECIFIED"
	}
}
