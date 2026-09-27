// Package rest registers the login feature's grpc-gateway translation onto
// the shared mux — the "HTTP gateway on top of gRPC" surface.
package rest

import (
	"context"

	"google.golang.org/grpc"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	authv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/auth/v1"
)

// RegisterREST wires POST /api/v1/auth/login onto mux via a loopback gRPC
// connection to this same server (conn).
func RegisterREST(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return authv1.RegisterAuthServiceHandler(ctx, mux, conn)
}
