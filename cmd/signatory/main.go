package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ecadlabs/signatory/cmd/commands"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	// Install backends
	_ "github.com/ecadlabs/signatory/pkg/vault/aws"
	_ "github.com/ecadlabs/signatory/pkg/vault/azure"
	_ "github.com/ecadlabs/signatory/pkg/vault/cloudkms"
	_ "github.com/ecadlabs/signatory/pkg/vault/file"
	_ "github.com/ecadlabs/signatory/pkg/vault/ledger"
	_ "github.com/ecadlabs/signatory/pkg/vault/mem"
	_ "github.com/ecadlabs/signatory/pkg/vault/yubi"
)

func newRootCommand(ctx context.Context) *cobra.Command {
	rootCtx := commands.Context{
		Context: ctx,
	}
	rootCmd := commands.NewRootCommand(&rootCtx, "signatory")
	serve := commands.NewServeCommand(&rootCtx)
	rootCmd.AddCommand(serve)
	rootCmd.RunE = serve.RunE

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
