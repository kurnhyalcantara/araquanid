package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

var configPath string

func execute() {
	if err := newRootCmd().Execute(); err != nil {
		slog.Error("command failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "araquanid",
		Short:         "araquanid service CLI",
		Long:          "araquanid is a gRPC-first microservice. The serve command runs the gRPC server, its REST gateway, and the ops server.",
		Version:       buildVersion,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&configPath, "config", "config/config.yaml",
		"path to the yaml config file, read first; ARAQUANID_ env vars override it")

	root.AddCommand(newServeCmd(), newVersionCmd())
	return root
}
