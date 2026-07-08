package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	platgrpc "github.com/kurnhyalcantara/kingler/pkg/platform/grpc"
	"github.com/kurnhyalcantara/kingler/pkg/platform/service"

	"github.com/kurnhyalcantara/araquanid/config"
	"github.com/kurnhyalcantara/araquanid/container"
)

// newServeCmd builds the command that runs the service.
func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the gRPC server, REST gateway, and ops server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			return serve(cmd.Context(), cfg)
		},
	}
}

func serve(ctx context.Context, cfg *config.Config) error {
	c, err := container.Build(ctx, cfg)
	if err != nil {
		return err
	}

	log := c.Logger
	ep := service.Registry[service.Auth]

	// The runner owns the gRPC + gateway lifecycle, but not the ops server
	// (metrics/health kept off the public port); run it alongside and shut it
	// down via an OnShutdown hook.
	opsServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.MetricsPort),
		Handler:           opsMux(c),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info("ops server listening (metrics, health)", slog.Int("port", cfg.Server.MetricsPort))
		if err := opsServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Error("ops server failed", slog.String("error", err.Error()))
		}
	}()

	return platgrpc.Run(ctx, platgrpc.RunnerConfig{
		GRPCServer:      c.GRPCServer,
		GRPCAddr:        ep.GRPCListenAddr(),
		GatewayHandler:  c.GatewayMux,
		HTTPAddr:        ep.HTTPListenAddr(),
		ShutdownTimeout: cfg.Server.ShutdownTimeout,
		Logger:          log,
		OnShutdown: []func(context.Context) error{
			opsServer.Shutdown,
			c.Close,
		},
	})
}

// opsMux serves the operational endpoints kept off the public HTTP port.
func opsMux(c *container.Container) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", c.Telemetry.MetricsHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := c.Ready(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
