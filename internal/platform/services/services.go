package services

import (
	"errors"
	"fmt"

	platgrpc "github.com/kurnhyalcantara/kingler/pkg/platform/grpc"
	"github.com/kurnhyalcantara/kingler/pkg/platform/service"
	identityv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/kurnhyalcantara/araquanid/config"
)

type GrpcServices struct {
	Identity identityv1.IdentityServiceClient

	Loopback *grpc.ClientConn

	conns []*grpc.ClientConn
}

func InitGrpcConns(cfg *config.Config) (*GrpcServices, error) {

	identityConn, err := newGrpcConn(cfg.Services.Identity.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Identity service connection: %w", err)
	}

	loopbackConn, err := platgrpc.NewLoopbackClient(service.Registry[service.Auth].GRPCPort)
	if err != nil {
		_ = identityConn.Close()
		return nil, fmt.Errorf("failed to initialize loopback connection: %w", err)
	}

	return &GrpcServices{
		Identity: identityv1.NewIdentityServiceClient(identityConn),
		Loopback: loopbackConn,
		conns:    []*grpc.ClientConn{identityConn, loopbackConn},
	}, nil
}

// Close closes every connection opened by InitGrpcConns.
func (s *GrpcServices) Close() error {
	errs := make([]error, 0, len(s.conns))
	for _, conn := range s.conns {
		errs = append(errs, conn.Close())
	}
	return errors.Join(errs...)
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
