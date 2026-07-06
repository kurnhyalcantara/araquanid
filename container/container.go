// Package container is the application's composition root: Build wires
// configuration, infrastructure, repositories, usecases, handlers, and
// middleware into runnable servers; Close releases everything in reverse
// order.
package container

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5/pgxpool"

	authv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/auth/v1"
	redislib "github.com/redis/go-redis/v9"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/kurnhyalcantara/kingler/pkg/middleware"
	platgrpc "github.com/kurnhyalcantara/kingler/pkg/platform/grpc"
	"github.com/kurnhyalcantara/kingler/pkg/platform/logger"
	"github.com/kurnhyalcantara/kingler/pkg/platform/postgres"

	"github.com/kurnhyalcantara/kingler/pkg/platform/redis"
	"github.com/kurnhyalcantara/kingler/pkg/platform/telemetry"
	platvalidator "github.com/kurnhyalcantara/kingler/pkg/platform/validator"

	"github.com/kurnhyalcantara/araquanid/config"
	domain_auth "github.com/kurnhyalcantara/araquanid/internal/domain/auth"
	authgrpc "github.com/kurnhyalcantara/araquanid/internal/features/auth/delivery/grpc"
	authrest "github.com/kurnhyalcantara/araquanid/internal/features/auth/delivery/rest"
	authidentity "github.com/kurnhyalcantara/araquanid/internal/features/auth/repository/identity"
	authdb "github.com/kurnhyalcantara/araquanid/internal/features/auth/repository/postgres"
	authredis "github.com/kurnhyalcantara/araquanid/internal/features/auth/repository/redis"
	authusecase "github.com/kurnhyalcantara/araquanid/internal/features/auth/usecase"
	examplerest "github.com/kurnhyalcantara/araquanid/internal/features/example/delivery/rest"
	"github.com/kurnhyalcantara/araquanid/internal/validator"
)

type Container struct {
	Config    *config.Config
	Logger    *slog.Logger
	Postgres  *pgxpool.Pool
	Redis     *redislib.Client
	Telemetry *telemetry.Telemetry

	GRPCServer   *grpclib.Server
	HealthServer *health.Server
	GatewayMux   *runtime.ServeMux

	gatewayConn *grpclib.ClientConn
}

// Build constructs the full application graph.
func Build(ctx context.Context, cfg *config.Config) (*Container, error) {
	log := logger.New(logger.Config{
		Level:   cfg.Log.Level,
		Format:  cfg.Log.Format,
		Name:    cfg.App.Name,
		Version: cfg.App.Version,
		Env:     cfg.App.Env,
	})

	tel, err := telemetry.New(ctx, telemetry.Config{
		Name:         cfg.App.Name,
		Version:      cfg.App.Version,
		Env:          cfg.App.Env,
		Enabled:      cfg.Telemetry.Enabled,
		OTLPEndpoint: cfg.Telemetry.OTLPEndpoint,
		SampleRatio:  cfg.Telemetry.SampleRatio,
	})
	if err != nil {
		return nil, fmt.Errorf("container: %w", err)
	}

	pg, err := postgres.New(ctx, postgres.Config{
		DSN:             cfg.Postgres.DSN(),
		MaxConns:        cfg.Postgres.MaxConns,
		MinConns:        cfg.Postgres.MinConns,
		MaxConnLifetime: cfg.Postgres.MaxConnLifetime,
	})
	if err != nil {
		return nil, fmt.Errorf("container: %w", err)
	}

	rdb, err := redis.New(ctx, redis.Config{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err != nil {
		pg.Close()
		return nil, fmt.Errorf("container: %w", err)
	}

	baseValidator := platvalidator.New()

	// Auth feature: identity ACL + repositories -> usecase -> handler.
	// TODO: dial the Identity Context (cfg.Identity.Addr) once provisioned; until
	// then the ACL is unconfigured and identity lookups report unavailable.
	authIdentityACL := authidentity.NewACL(nil)
	authUsecase := authusecase.New(
		authusecase.Dependencies{
			CredentialRepository:   authdb.NewPostgresCredentialRepository(pg),
			LoginAttemptRepository: authdb.NewPostgresLoginAttemptRepository(pg),
			MFARepository:          authdb.NewPostgresMFARepository(pg),
			MFASessionStore:        authredis.NewRedisMFASessionStore(rdb, cfg.Redis.CacheTTL),
			IdentityACL:            authIdentityACL,
			Config: domain_auth.Config{
				LockoutThreshold:      cfg.Auth.Lockout.Threshold,
				LockoutWindow:         cfg.Auth.Lockout.Window,
				LockoutTier1Duration:  cfg.Auth.Lockout.Tier1Duration,
				LockoutTier2Duration:  cfg.Auth.Lockout.Tier2Duration,
				MFASessionWindow:      cfg.Auth.Session.MFASessionWindow,
				AccessTTL:             cfg.Auth.Token.AccessTTL,
				RecoveryCodeLowThresh: cfg.Auth.MFA.RecoveryCodeLowThreshold,
			},
		},
	)
	authHandler := authgrpc.NewHandler(authUsecase, validator.New(baseValidator))

	// Interceptor chain, outermost first.
	grpcServer, healthServer := platgrpc.NewServer(
		middleware.RequestID(),
		middleware.Recovery(log),
		middleware.Logging(log),
		middleware.AppError(),
	)

	authv1.RegisterAuthServiceServer(grpcServer, authHandler)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	gatewayMux := platgrpc.NewGatewayMux(middleware.GatewayOptions()...)
	gatewayConn, err := platgrpc.NewLoopbackClient(cfg.Server.GRPCPort)
	if err != nil {
		pg.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("container: %w", err)
	}
	if err := examplerest.RegisterREST(ctx, gatewayMux, gatewayConn); err != nil {
		pg.Close()
		_ = rdb.Close()
		_ = gatewayConn.Close()
		return nil, fmt.Errorf("container: %w", err)
	}
	if err := authrest.RegisterREST(ctx, gatewayMux, gatewayConn); err != nil {
		pg.Close()
		_ = rdb.Close()
		_ = gatewayConn.Close()
		return nil, fmt.Errorf("container: %w", err)
	}

	return &Container{
		Config:       cfg,
		Logger:       log,
		Postgres:     pg,
		Redis:        rdb,
		Telemetry:    tel,
		GRPCServer:   grpcServer,
		HealthServer: healthServer,
		GatewayMux:   gatewayMux,
		gatewayConn:  gatewayConn,
	}, nil
}

// Ready reports whether downstream dependencies are reachable; it backs the
// /readyz endpoint.
func (c *Container) Ready(ctx context.Context) error {
	if err := c.Postgres.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	if err := c.Redis.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	return nil
}

// Close releases resources in reverse dependency order. The gRPC server
// must already be stopped by the caller.
func (c *Container) Close(ctx context.Context) error {
	errs := []error{
		c.gatewayConn.Close(),
		c.Redis.Close(),
		c.Telemetry.Shutdown(ctx),
	}
	c.Postgres.Close()
	return errors.Join(errs...)
}
