package services

import (
	"fmt"

	"github.com/kurnhyalcantara/araquanid/config"
	identityv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GrpcServices struct {
	Identity identityv1.IdentityServiceClient
}

func InitGrpcConns(cfg *config.Config) (*GrpcServices, error) {

	identityConn, err := newGrpcConn(cfg.Services.Identity.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Identity service connection: %w", err)
	}

	return &GrpcServices{
		Identity: identityv1.NewIdentityServiceClient(identityConn),
	}, nil
}

func newGrpcConn(addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	if addr == "" {
		return nil, fmt.Errorf("address cannot be empty")
	}

	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	return conn, nil
}
