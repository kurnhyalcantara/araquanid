// Package grpc implements authv1.AuthServiceServer's Login RPC: validate ->
// map -> usecase -> map (per docs/ARCHITECTURE.md's thin-handler convention).
package grpc

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	authv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/auth/v1"

	"github.com/kurnhyalcantara/araquanid/internal/features/login/delivery/grpc/mapper"
	"github.com/kurnhyalcantara/araquanid/internal/features/login/usecase"
	"github.com/kurnhyalcantara/araquanid/internal/validator"
)

// Handler implements authv1.AuthServiceServer. VerifyMfa is a separate,
// out-of-scope feature — embedding UnimplementedAuthServiceServer satisfies
// the interface for it (returns codes.Unimplemented until that feature adds
// its own handler).
type Handler struct {
	authv1.UnimplementedAuthServiceServer
	usecase   *usecase.Usecase
	validator *validator.Validator
}

// NewHandler builds a Handler.
func NewHandler(uc *usecase.Usecase, v *validator.Validator) *Handler {
	return &Handler{usecase: uc, validator: v}
}

func (h *Handler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	in := mapper.ToDTO(req)
	if err := h.validator.Login(in); err != nil {
		return nil, err
	}

	ip := clientIP(ctx)
	userAgent := headerValue(ctx, "grpcgateway-user-agent", "user-agent")
	acceptLanguage := headerValue(ctx, "grpcgateway-accept-language", "accept-language")

	result, err := h.usecase.Login(ctx, mapper.ToUsecaseInput(in, ip, userAgent, acceptLanguage))
	if err != nil {
		return nil, err
	}
	return mapper.ToProtoResponse(result), nil
}

// clientIP prefers the first hop of X-Forwarded-For (as grpc-gateway
// forwards it, FR-POST-AUTH-001), falling back to the gRPC peer address for
// direct (non-gateway) callers.
func clientIP(ctx context.Context) netip.Addr {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			first := strings.TrimSpace(strings.Split(xff[0], ",")[0])
			if addr, err := netip.ParseAddr(first); err == nil {
				return addr
			}
		}
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			if addr, err := netip.ParseAddr(host); err == nil {
				return addr
			}
		}
	}
	return netip.Addr{}
}

// headerValue reads the first present header among keys, checking the
// grpc-gateway-forwarded form before the raw gRPC metadata key, truncated to
// 512 chars (FR-POST-AUTH-001 / FR-DEVICE-001).
func headerValue(ctx context.Context, keys ...string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, k := range keys {
		if v := md.Get(k); len(v) > 0 {
			return truncateHeader(v[0], 512)
		}
	}
	return ""
}

func truncateHeader(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
