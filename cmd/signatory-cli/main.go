package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ecadlabs/signatory/cmd/commands"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ecadlabs/signatory/pkg/vault"
	// Install backends
	_ "github.com/ecadlabs/signatory/pkg/vault/preamble"
)

func newRootCommand(ctx context.Context) *cobra.Command {
	rootCtx := commands.Context{
		Context: ctx,
	}
	rootCmd := commands.NewRootCommand(&rootCtx, "signatory-cli")
	rootCmd.AddCommand(
		commands.NewListCommand(&rootCtx),
		commands.NewImportCommand(&rootCtx),
		commands.NewGenerateCommand(&rootCtx),
		commands.NewVersionCommand(&rootCtx),
		commands.NewListRequests(&rootCtx),
		commands.NewListOps(&rootCtx),
	)

	// Vault specific
	rootCmd.AddCommand(vault.Commands()...)

	return rootCmd
}

func main() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		s := <-signalChan
		log.Printf("Captured %v\n", s)
		cancel()
	}()

	if err := newRootCommand(ctx).Execute(); err != nil {
		os.Exit(1)
	}
}
