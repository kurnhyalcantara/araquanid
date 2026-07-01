package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// Build metadata, injected via -ldflags at build time (see the Makefile). They
// default to "dev"/"none" for `go run` and unstamped builds.
var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// configPath is bound to the persistent --config flag and consumed by the
// subcommands that load configuration.
var configPath string

// Execute runs the CLI and converts a command error into a non-zero exit.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		slog.Error("command failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// newRootCmd assembles the command tree. The root has no run behaviour of its own;
// `serve` runs the service.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "araquanid",
		Short:         "araquanid service CLI",
		Long:          "araquanid is a gRPC-first microservice. The serve command runs the gRPC server, its REST gateway, and the ops server.",
		Version:       buildVersion,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&configPath, "config", "",
		"optional path to a yaml config file to layer under env vars (defaults + env are the source of truth)")

	root.AddCommand(newServeCmd(), newVersionCmd())
	return root
}
