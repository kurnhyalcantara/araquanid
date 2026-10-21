// Package container is the application's composition root
package container

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5/pgxpool"

	redislib "github.com/redis/go-redis/v9"
	kafkago "github.com/segmentio/kafka-go"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	platmiddleware "github.com/kurnhyalcantara/kingler/pkg/middleware"
	platgrpc "github.com/kurnhyalcantara/kingler/pkg/platform/grpc"
	"github.com/kurnhyalcantara/kingler/pkg/platform/logger"
	"github.com/kurnhyalcantara/kingler/pkg/platform/postgres"
	"github.com/kurnhyalcantara/kingler/pkg/platform/redis"
	"github.com/kurnhyalcantara/kingler/pkg/platform/telemetry"
	platvalidator "github.com/kurnhyalcantara/kingler/pkg/platform/validator"

	authv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/auth/v1"

	"github.com/kurnhyalcantara/araquanid/config"
	"github.com/kurnhyalcantara/araquanid/internal/domain"
	logingrpc "github.com/kurnhyalcantara/araquanid/internal/features/login/delivery/grpc"
	loginrest "github.com/kurnhyalcantara/araquanid/internal/features/login/delivery/rest"
	logindb "github.com/kurnhyalcantara/araquanid/internal/features/login/repository/db"
	loginidentity "github.com/kurnhyalcantara/araquanid/internal/features/login/repository/identity"
	loginredis "github.com/kurnhyalcantara/araquanid/internal/features/login/repository/redis"
	loginusecase "github.com/kurnhyalcantara/araquanid/internal/features/login/usecase"
	"github.com/kurnhyalcantara/araquanid/internal/middleware"
	"github.com/kurnhyalcantara/araquanid/internal/platform/jwtsign"
	"github.com/kurnhyalcantara/araquanid/internal/platform/outbox"
	"github.com/kurnhyalcantara/araquanid/internal/platform/passwordhash"
	"github.com/kurnhyalcantara/araquanid/internal/platform/ratelimit"
	"github.com/kurnhyalcantara/araquanid/internal/platform/services"
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

	clients     *services.GrpcServices
	kafkaWriter *kafkago.Writer
	relayCancel context.CancelFunc
}

// Build constructs the full application graph.
func Build(ctx context.Context, cfg *config.Config) (con *Container, err error) {
	con = &Container{Config: cfg}

	defer func() {
		if err != nil {
			_ = con.Close(ctx)
			con = nil
		}
	}()

	con.Logger = logger.New(logger.Config{
		Level:   cfg.Log.Level,
		Format:  cfg.Log.Format,
		Name:    cfg.App.Name,
		Version: cfg.App.Version,
		Env:     cfg.App.Env,
	})

	con.Telemetry, err = telemetry.New(ctx, telemetry.Config{
		Name:         cfg.App.Name,
		Version:      cfg.App.Version,
		Env:          cfg.App.Env,
		Enabled:      cfg.Telemetry.Enabled,
		OTLPEndpoint: cfg.Telemetry.OTLPEndpoint,
		SampleRatio:  cfg.Telemetry.SampleRatio,
	})
	if err != nil {
		err = fmt.Errorf("failed init telemetry: %w", err)
		return
	}

	con.Postgres, err = postgres.New(ctx, postgres.Config{
		DSN:             cfg.Postgres.DSN(),
		MaxConns:        cfg.Postgres.MaxConns,
		MinConns:        cfg.Postgres.MinConns,
		MaxConnLifetime: cfg.Postgres.MaxConnLifetime,
	})
	if err != nil {
		err = fmt.Errorf("failed init postgres: %w", err)
		return
	}

	con.Redis, err = redis.New(ctx, redis.Config{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err != nil {
		err = fmt.Errorf("failed init redis: %w", err)
		return
	}

	signer, err := jwtsign.NewSigner(jwtsign.Config{
		PrivateKeyPEM:  cfg.Auth.Token.PrivateKeyPEM,
		PrivateKeyPath: cfg.Auth.Token.PrivateKeyPath,
		Kid:            cfg.Auth.Token.Kid,
		Issuer:         cfg.Auth.Token.Issuer,
	})
	if err != nil {
		err = fmt.Errorf("failed init jwt signer: %w", err)
		return
	}

	con.clients, err = services.InitGrpcConns(cfg)
	if err != nil {
		err = fmt.Errorf("failed init grpc services: %w", err)
		return
	}

	relayCtx, relayCancel := context.WithCancel(context.Background())
	con.relayCancel = relayCancel

	con.kafkaWriter = &kafkago.Writer{
		Addr:     kafkago.TCP(cfg.Kafka.Brokers...),
		Topic:    cfg.Kafka.OutboxTopic,
		Balancer: &kafkago.LeastBytes{},
	}

	relay := outbox.NewRelay(con.Postgres, con.kafkaWriter, outbox.RelayConfig{
		PollInterval: cfg.Kafka.PublishInterval,
		BatchSize:    cfg.Kafka.BatchSize,
	}, con.Logger)

	go func() {
		if err := relay.Run(relayCtx); err != nil && !errors.Is(err, context.Canceled) {
			con.Logger.Error("outbox relay stopped", slog.String("error", err.Error()))
		}
	}()

	con.GRPCServer, con.HealthServer = platgrpc.NewServer(
		platmiddleware.RequestID(),
		platmiddleware.Recovery(con.Logger),
		platmiddleware.Logging(con.Logger),
		middleware.AppError(),
	)

	loginRepo := logindb.New(con.Postgres)
	mfaSessions := loginredis.NewMFASessionStore(con.Redis)
	identityACL := loginidentity.NewACL(con.clients.Identity)
	rateLimiter := ratelimit.New(con.Redis)

	loginUC := loginusecase.New(loginusecase.Dependencies{
		UnitOfWork:      loginRepo,
		Credentials:     loginRepo,
		Devices:         loginRepo,
		MFAFactors:      loginRepo,
		LoginAttempts:   loginRepo,
		IdentityACL:     identityACL,
		MFASessionStore: mfaSessions,
		RateLimiter:     rateLimiter,
		TokenSigner:     signer,
		Logger:          con.Logger,
		Config: loginusecase.Config{
			Lockout: domain.LockoutPolicy{
				Threshold:          cfg.Auth.Lockout.Threshold,
				Window:             cfg.Auth.Lockout.Window,
				TemporaryDurations: []time.Duration{cfg.Auth.Lockout.Tier1Duration, cfg.Auth.Lockout.Tier2Duration},
			},
			CredentialPolicy: domain.DefaultCredentialPolicy(),
			SessionPolicy: domain.SessionPolicy{
				IdleTimeout:      cfg.Auth.Session.IdleTimeoutWeb,
				AbsoluteLifetime: cfg.Auth.Session.AbsoluteWeb,
			},
			ConcurrentPolicy:   cfg.Auth.Session.ConcurrentPolicy,
			ConcurrentMax:      cfg.Auth.Session.ConcurrentMax,
			MFASessionWindow:   cfg.Auth.Session.MFASessionWindow,
			ForcedChangeWindow: cfg.Auth.Session.ForcedChangeWindow,
			AccessTokenTTL:     cfg.Auth.Token.AccessTTL,
			RefreshTokenTTL:    cfg.Auth.Token.RefreshTTLWeb,
			Argon2id: passwordhash.Argon2idParams{
				TimeCost:    cfg.Auth.Argon2id.TimeCost,
				MemoryKB:    cfg.Auth.Argon2id.MemoryKB,
				Parallelism: cfg.Auth.Argon2id.Parallelism,
			},
			FingerprintVersion: cfg.Auth.Device.FingerprintVersion,
			RateLimit: loginusecase.RateLimitConfig{
				IPMaxAttempts:       cfg.Auth.RateLimit.IPMaxAttempts,
				IPWindow:            cfg.Auth.RateLimit.IPWindow,
				IdentityMaxAttempts: cfg.Auth.RateLimit.IdentityMaxAttempts,
				IdentityWindow:      cfg.Auth.RateLimit.IdentityWindow,
			},
		},
	})

	baseValidator := platvalidator.New()
	val := validator.New(baseValidator)
	loginHandler := logingrpc.NewHandler(loginUC, val)

	authv1.RegisterAuthServiceServer(con.GRPCServer, loginHandler)
	con.HealthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	con.GatewayMux = platgrpc.NewGatewayMux(middleware.GatewayOptions()...)
	err = loginrest.RegisterREST(ctx, con.GatewayMux, con.clients.Loopback)
	if err != nil {
		err = fmt.Errorf("failed init login REST gateway: %w", err)
		return
	}

	return
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
// must already be stopped by the caller. It is safe to call on a partially
// built Container.
func (c *Container) Close(ctx context.Context) error {
	var errs []error
	if c.relayCancel != nil {
		c.relayCancel()
	}
	if c.clients != nil {
		errs = append(errs, c.clients.Close())
	}
	if c.kafkaWriter != nil {
		errs = append(errs, c.kafkaWriter.Close())
	}
	if c.Redis != nil {
		errs = append(errs, c.Redis.Close())
	}
	if c.Postgres != nil {
		c.Postgres.Close()
	}
	if c.Telemetry != nil {
		errs = append(errs, c.Telemetry.Shutdown(ctx))
	}
	return errors.Join(errs...)
}
