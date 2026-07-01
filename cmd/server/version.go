package main

import (
	"github.com/spf13/cobra"
)

// newVersionCmd prints build metadata stamped in at link time.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build version, commit, and date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf("araquanid %s\n  commit: %s\n  built:  %s\n",
				buildVersion, buildCommit, buildDate)
			return nil
		},
	}
}
