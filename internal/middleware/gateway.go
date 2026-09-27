package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/kurnhyalcantara/kingler/pkg/constants"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	"github.com/kurnhyalcantara/araquanid/internal/apperror"
)

// GatewayOptions mirrors kingler's middleware.GatewayOptions shape (error
// handler + header matcher) but renders the PRD §13 error envelope: HTTP 200
// for business-logic outcomes, a top-level code/code_client pair, instead of
// grpc-gateway's default runtime.HTTPStatusFromCode status + bare message.
func GatewayOptions() []runtime.ServeMuxOption {
	return []runtime.ServeMuxOption{
		runtime.WithErrorHandler(errorHandler),
		runtime.WithIncomingHeaderMatcher(headerMatcher),
	}
}

type errorBody struct {
	Code       string            `json:"code"`
	CodeClient string            `json:"code_client"`
	Message    string            `json:"message"`
	Details    map[string]string `json:"details,omitempty"`
}

func errorHandler(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
	st := status.Convert(err)
	code, details := recoverCode(st)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apperror.HTTPStatus(code))
	_ = json.NewEncoder(w).Encode(errorBody{
		Code:       string(code),
		CodeClient: apperror.CodeClient(code),
		Message:    st.Message(),
		Details:    details,
	})
}

// recoverCode recovers the original apperror.Code from the errdetails.ErrorInfo
// attached by middleware.AppError() — a bare gRPC status code alone would lose
// it, since many distinct PRD codes collapse onto the same handful of gRPC
// codes. A status with no such detail (e.g. a recovered panic, or any future
// error path that bypasses AppError()) falls back to a generic system error,
// which is the correct shape for that case too (HTTP 500, code_client "07").
func recoverCode(st *status.Status) (apperror.Code, map[string]string) {
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.Domain == errorInfoDomain {
			return apperror.Code(info.Reason), info.Metadata
		}
	}
	return apperror.ErrSystemInternal, nil
}

func headerMatcher(key string) (string, bool) {
	switch strings.ToLower(key) {
	case constants.HeaderAuthorization, constants.HeaderRequestID:
		return strings.ToLower(key), true
	default:
		return runtime.DefaultHeaderMatcher(key)
	}
}
