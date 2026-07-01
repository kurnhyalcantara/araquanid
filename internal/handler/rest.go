package handler

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	examplev1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/example/v1"
	"google.golang.org/grpc"
)

// RegisterREST wires ExampleService's REST routes (from the proto http
// annotations) into the gateway mux, forwarding over the given connection.
func RegisterREST(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	if err := examplev1.RegisterExampleServiceHandler(ctx, mux, conn); err != nil {
		return fmt.Errorf("example rest: register gateway handler: %w", err)
	}
	return nil
}
