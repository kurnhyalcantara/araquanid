// Package apperror is araquanid's application-level error catalog (PRD §13).
// Unlike kingler's pkg/apperror (a small, closed set of transport-agnostic
// codes), this catalog carries the PRD's own "ERR-XXX-NNN" business codes and
// their HTTP/gRPC/code_client mapping, since business-outcome errors here are
// deliberately transported as HTTP 200 — a contract kingler's generic
// catalog and grpc-gateway's default status mapping cannot express.
package apperror

import (
	"fmt"
	"maps"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
)

// Code is an application-level outcome code (PRD §13). "00" means success;
// every other value is an "ERR-<AREA>-<NNN>" string from the PRD's catalog.
type Code string

// Success is the code carried by every successful response.
const Success Code = "00"

// Codes reachable from the Login use case (PRD §13.0, §13.1, §13.7, §13.8).
// ERR-LOGIN-002 (identity-inactive) is deliberately not a distinct exported
// code: FR-LOGIN-003 requires an identity-inactive response to be identical
// to invalid-credentials, so both collapse onto ErrLoginInvalidCredentials.
const (
	ErrRequestValidation Code = "ERR-REQUEST-003" // malformed body / schema violation

	ErrLoginInvalidCredentials Code = "ERR-LOGIN-001"
	ErrLoginAccountLocked      Code = "ERR-LOGIN-003"

	ErrRateLimited Code = "ERR-RATE-001"

	ErrSystemDatabase Code = "ERR-SYS-001" // Postgres unavailable
	ErrSystemUpstream Code = "ERR-SYS-002" // Identity Context / Redis / Kafka unavailable
	ErrSystemInternal Code = "ERR-SYS-003" // unexpected / panic-recovered
)

// entry is the catalog's per-code metadata: the client-facing bucket
// (PRD §13.9), the real HTTP status to use (0 means "always 200 — a
// business outcome, never a transport failure"), and the gRPC status the
// AppError interceptor raises so native gRPC clients get an equivalent
// signal without needing a body.
type entry struct {
	codeClient string
	httpStatus int
	grpcCode   codes.Code
}

var catalog = map[Code]entry{
	Success:                    {codeClient: "00"},
	ErrRequestValidation:       {codeClient: "01", grpcCode: codes.InvalidArgument},
	ErrLoginInvalidCredentials: {codeClient: "02", grpcCode: codes.Unauthenticated},
	ErrLoginAccountLocked:      {codeClient: "03", grpcCode: codes.PermissionDenied},
	ErrRateLimited:             {codeClient: "04", httpStatus: 429, grpcCode: codes.ResourceExhausted},
	ErrSystemDatabase:          {codeClient: "07", httpStatus: 503, grpcCode: codes.Unavailable},
	ErrSystemUpstream:          {codeClient: "07", httpStatus: 502, grpcCode: codes.Unavailable},
	ErrSystemInternal:          {codeClient: "07", httpStatus: 500, grpcCode: codes.Internal},
}

// lookup returns the catalog entry for c, defaulting to an internal-error
// shape for any code not registered above (should not happen in practice —
// every Code constant has a matching catalog entry).
func lookup(c Code) entry {
	if e, ok := catalog[c]; ok {
		return e
	}
	return entry{codeClient: "07", httpStatus: 500, grpcCode: codes.Internal}
}

// CodeClient returns the 2-digit client-facing bucket for c (PRD §13.9).
func CodeClient(c Code) string { return lookup(c).codeClient }

// HTTPStatus returns the real HTTP status to use for c. Per the PRD, this is
// 200 for every business-logic outcome; only the rate-limit family and
// system errors keep a real non-200 status.
func HTTPStatus(c Code) int {
	if s := lookup(c).httpStatus; s != 0 {
		return s
	}
	return 200
}

// GRPCStatus returns the gRPC status code to raise for c over the native
// gRPC transport.
func GRPCStatus(c Code) codes.Code { return lookup(c).grpcCode }

// Error is the real error-path type: a *Error is only ever constructed for
// codes that should propagate as a Go error (rate limiting, system
// failures, request validation) — business outcomes like invalid
// credentials or a locked account are returned as ordinary values from a
// usecase (see internal/features/login/usecase), never as *Error, so they
// never take this path.
type Error struct {
	Code    Code
	Message string
	// Details carries small string key/value pairs the client needs to act
	// on the error, e.g. {"retry_after": "30"} or {"locked_until": "..."}.
	Details map[string]string
	cause   error
}

func New(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// RateLimited builds an ErrRateLimited *Error carrying retry_after (seconds)
// as a detail (FR-LOGIN-008, PRD §13.7).
func RateLimited(retryAfter time.Duration) *Error {
	return New(ErrRateLimited, "too many requests").
		WithDetail("retry_after", strconv.Itoa(int(retryAfter.Seconds())))
}

func Wrap(code Code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, cause: cause}
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.cause }

// WithDetail returns a copy of e with a detail key/value added.
func (e *Error) WithDetail(key, value string) *Error {
	details := make(map[string]string, len(e.Details)+1)
	maps.Copy(details, e.Details)
	details[key] = value
	return &Error{Code: e.Code, Message: e.Message, Details: details, cause: e.cause}
}
