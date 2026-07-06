// Package grpc is the gRPC inbound adapter for the auth feature. It validates
// requests, maps them to dtos, delegates to the usecase, and maps results back
// to transport types. The REST surface is the same handler reached through the
// grpc-gateway (see the sibling delivery/rest package).
package grpc

import (
	"context"
	"strings"

	authv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/auth/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	domain_auth "github.com/kurnhyalcantara/araquanid/internal/domain/auth"
	"github.com/kurnhyalcantara/araquanid/internal/features/auth/delivery/grpc/mapper"
	"github.com/kurnhyalcantara/araquanid/internal/validator"
)

type Handler struct {
	authv1.UnimplementedAuthServiceServer

	usecase   domain_auth.Usecase
	validator *validator.Validator
}

func NewHandler(uc domain_auth.Usecase, val *validator.Validator) *Handler {
	return &Handler{usecase: uc, validator: val}
}

func (h *Handler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	in := mapper.ToLoginInputDTO(req)
	if err := h.validator.Login(in); err != nil {
		return nil, err
	}

	res, err := h.usecase.Login(ctx, mapper.ToLoginInput(in, clientIP(ctx), userAgent(ctx)))
	if err != nil {
		return nil, err
	}
	return mapper.ToLoginResponse(res), nil
}

// clientIP derives the caller IP from the forwarded header (first hop) or the
// peer address (FR-POST-AUTH-001). Full X-Forwarded-For validation is deferred
// with the login logic.
func clientIP(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 && xff[0] != "" {
			return strings.TrimSpace(strings.Split(xff[0], ",")[0])
		}
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

// userAgent reads the User-Agent forwarded by the grpc-gateway or the gRPC
// client, truncated per FR-POST-AUTH-001.
func userAgent(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range []string{"grpcgateway-user-agent", "user-agent"} {
		if v := md.Get(key); len(v) > 0 && v[0] != "" {
			return truncate(v[0], 512)
		}
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}
