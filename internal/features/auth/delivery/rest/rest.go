// Package rest registers the auth feature's REST surface, derived from the
// proto contract's http annotations, onto the shared grpc-gateway mux.
package rest

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	authv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/auth/v1"
	"google.golang.org/grpc"
)

// RegisterREST wires AuthService's REST routes (from the proto http
// annotations) into the gateway mux, forwarding over the given connection.
func RegisterREST(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	if err := authv1.RegisterAuthServiceHandler(ctx, mux, conn); err != nil {
		return fmt.Errorf("auth rest: register gateway handler: %w", err)
	}
	return nil
}
