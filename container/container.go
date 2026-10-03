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
	"github.com/kurnhyalcantara/kingler/pkg/platform/service"
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

	clients     *platgrpc.Clients
	kafkaWriter *kafkago.Writer
	relayCancel context.CancelFunc
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
		_ = tel.Shutdown(ctx)
		return nil, fmt.Errorf("container: %w", err)
	}

	rdb, err := redis.New(ctx, redis.Config{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err != nil {
		_ = tel.Shutdown(ctx)
		pg.Close()
		return nil, fmt.Errorf("container: %w", err)
	}

	signer, err := jwtsign.NewSigner(jwtsign.Config{
		PrivateKeyPEM:  cfg.Auth.Token.PrivateKeyPEM,
		PrivateKeyPath: cfg.Auth.Token.PrivateKeyPath,
		Kid:            cfg.Auth.Token.Kid,
		Issuer:         cfg.Auth.Token.Issuer,
	})
	if err != nil {
		_ = tel.Shutdown(ctx)
		pg.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("container: %w", err)
	}

	// Outbound gRPC clients: the gateway's loopback connection to this process's
	// own server, plus the Identity Context (added only when its endpoint is
	// configured). Ports come from the shared service catalog so the bind and
	// dial sides cannot drift.
	ep := service.Registry[service.Auth]
	clientsCfg := platgrpc.ClientsConfig{
		"loopback": {Target: ep.GRPCTarget("localhost")},
	}
	if cfg.Identity.Addr != "" {
		clientsCfg["identity"] = platgrpc.ClientConfig{Target: cfg.Identity.Addr}
	}
	clients, err := platgrpc.NewClients(clientsCfg)
	if err != nil {
		_ = tel.Shutdown(ctx)
		pg.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("container: %w", err)
	}

	// Outbox relay: publishes transactionally-written domain events (PRD
	// §10.4) to Kafka in the background; stopped via relayCancel in Close.
	kafkaWriter := &kafkago.Writer{
		Addr:     kafkago.TCP(cfg.Kafka.Brokers...),
		Topic:    cfg.Kafka.OutboxTopic,
		Balancer: &kafkago.LeastBytes{},
	}
	relayCtx, relayCancel := context.WithCancel(context.Background())
	relay := outbox.NewRelay(pg, kafkaWriter, outbox.RelayConfig{
		PollInterval: cfg.Kafka.PublishInterval,
		BatchSize:    cfg.Kafka.BatchSize,
	}, log)
	go func() {
		if err := relay.Run(relayCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("outbox relay stopped", slog.String("error", err.Error()))
		}
	}()

	// Interceptor chain, outermost first. AppError/GatewayOptions are
	// araquanid's own (internal/middleware), not kingler's — the PRD's error
	// envelope (HTTP 200 for business errors, top-level code/code_client) is
	// the app-wide standard from here on, not a login-only exception.
	grpcServer, healthServer := platgrpc.NewServer(
		platmiddleware.RequestID(),
		platmiddleware.Recovery(log),
		platmiddleware.Logging(log),
		middleware.AppError(),
	)

	loginRepo := logindb.New(pg)
	mfaSessions := loginredis.NewMFASessionStore(rdb)
	identityACL := loginidentity.NewACL(clients.Get("identity"))
	rateLimiter := ratelimit.New(rdb)

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
		Logger:          log,
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

	authv1.RegisterAuthServiceServer(grpcServer, loginHandler)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	gatewayMux := platgrpc.NewGatewayMux(middleware.GatewayOptions()...)
	gatewayConn := clients.Get("loopback")
	if err := loginrest.RegisterREST(ctx, gatewayMux, gatewayConn); err != nil {
		relayCancel()
		pg.Close()
		_ = rdb.Close()
		_ = clients.Close()
		_ = kafkaWriter.Close()
		return nil, fmt.Errorf("container: register login REST gateway: %w", err)
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
		clients:      clients,
		kafkaWriter:  kafkaWriter,
		relayCancel:  relayCancel,
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
	c.relayCancel()
	errs := []error{
		c.clients.Close(),
		c.Redis.Close(),
		c.kafkaWriter.Close(),
		c.Telemetry.Shutdown(ctx),
	}
	c.Postgres.Close()
	return errors.Join(errs...)
}
