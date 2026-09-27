// Package middleware replaces kingler's pkg/middleware AppError/GatewayOptions
// for the parts of the error contract the PRD (§13) requires kingler's
// generic 6-code catalog cannot express: HTTP 200 for business-logic errors,
// and a top-level code/code_client pair in every error body. Every other
// kingler interceptor (RequestID, Recovery, Logging, Auth) is reused as-is.
package middleware

import (
	"context"
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/kurnhyalcantara/araquanid/internal/apperror"
)

// errorInfoDomain identifies araquanid as the errdetails.ErrorInfo domain so
// the gateway error handler can recover the original apperror.Code — which a
// bare gRPC status code alone would lose (many distinct PRD codes collapse
// onto the same handful of gRPC codes, e.g. both invalid-credentials and a
// future unrelated auth failure could both be codes.Unauthenticated).
const errorInfoDomain = "araquanid"

// AppError translates a *apperror.Error returned by a handler into a gRPC
// status, attaching the original Code (and any Details) as a standard
// errdetails.ErrorInfo so the HTTP gateway can recover it losslessly.
func AppError() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		if err == nil {
			return resp, nil
		}

		if appErr, ok := errors.AsType[*apperror.Error](err); ok {
			st, buildErr := status.New(apperror.GRPCStatus(appErr.Code), appErr.Message).WithDetails(
				&errdetails.ErrorInfo{
					Reason:   string(appErr.Code),
					Domain:   errorInfoDomain,
					Metadata: appErr.Details,
				},
			)
			if buildErr != nil {
				// Detail attachment failed (should not happen for a
				// well-formed proto message) — fall back to a plain status
				// so the RPC still fails with the right gRPC code.
				return nil, status.Error(apperror.GRPCStatus(appErr.Code), appErr.Message)
			}
			return nil, st.Err()
		}

		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
}
