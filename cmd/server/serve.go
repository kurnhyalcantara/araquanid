package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

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
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c, err := container.Build(ctx, cfg)
	if err != nil {
		return err
	}

	log := c.Logger

	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		return fmt.Errorf("listen grpc: %w", err)
	}

	gatewayServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler:           c.GatewayMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	opsServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.MetricsPort),
		Handler:           opsMux(c),
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 3)
	go func() {
		log.Info("grpc server listening", slog.Int("port", cfg.Server.GRPCPort))
		serveErr <- c.GRPCServer.Serve(grpcListener)
	}()
	go func() {
		log.Info("http gateway listening", slog.Int("port", cfg.Server.HTTPPort))
		if err := gatewayServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	go func() {
		log.Info("ops server listening (metrics, health)", slog.Int("port", cfg.Server.MetricsPort))
		if err := opsServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-serveErr:
		return fmt.Errorf("server failed: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	c.HealthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	_ = gatewayServer.Shutdown(shutdownCtx)
	_ = opsServer.Shutdown(shutdownCtx)
	gracefulStop(c.GRPCServer.GracefulStop, shutdownCtx)

	if err := c.Close(shutdownCtx); err != nil {
		log.Warn("cleanup finished with errors", slog.String("error", err.Error()))
	}
	log.Info("shutdown complete")
	return nil
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

// gracefulStop runs stop but abandons the wait if ctx expires first.
func gracefulStop(stop func(), ctx context.Context) {
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
