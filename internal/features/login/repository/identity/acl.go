// Package identity is the anti-corruption-layer adapter over the Identity
// bounded context (a separate microservice; identityv1.IdentityServiceClient
// is its gRPC contract, internal-only per identity.proto).
package identity

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"

	identityv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/identity/v1"

	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
)

// ErrUnavailable is returned when the Identity Context client was never
// configured (config.Identity.Addr empty) — every call fails closed rather
// than silently no-op'ing.
var ErrUnavailable = errors.New("login/identity: identity context unavailable")

type acl struct {
	client identityv1.IdentityServiceClient
}

// NewACL builds a repository.IdentityACL over conn. conn may be nil (no
// Identity Context endpoint configured); every call then returns
// ErrUnavailable instead of panicking.
func NewACL(conn *grpc.ClientConn) repository.IdentityACL {
	if conn == nil {
		return &acl{}
	}
	return &acl{client: identityv1.NewIdentityServiceClient(conn)}
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
