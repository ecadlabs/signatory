package cmd

import (
	"context"
	"net/http"
	"time"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/metrics"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	defaultAddr = ":80"
	// Registered here https://github.com/prometheus/prometheus/wiki/Default-port-allocations
	defaultUtilityAddr = ":9583"
)

// rootContext represents root command context shared with its children
type rootContext struct {
	context   context.Context
	config    *config.Config
	signatory *signatory.Signatory
}

// NewRootCommand returns new root command
func newRootCommand(ctx context.Context) *cobra.Command {
	var (
		level      string
		configFile string
	)

	c := rootContext{
		context: ctx,
	}

	rootCmd := &cobra.Command{
		Use:   "signatory",
		Short: "A Tezos Remote Signer for signing block-chain operations with private keys",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) (err error) {
			// cmd always points to the top level command!!!
			var conf config.Config
			if err := conf.Read(configFile); err != nil {
				return err
			}

			validate := config.Validator()
			if err := validate.Struct(&conf); err != nil {
				return err
			}

			lv, err := log.ParseLevel(level)
			if err != nil {
				return err
			}

			log.SetLevel(lv)

			sigConf := signatory.Config{
				Policy:      conf.Tezos,
				Vaults:      conf.Vaults,
				Interceptor: metrics.Interceptor,
				Watermark:   signatory.NewInMemoryWatermark(),
			}

			sig, err := signatory.NewSignatory(ctx, &sigConf)
			if err != nil {
				return err
			}

			c.config = &conf
			c.signatory = sig
			return nil
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			srvConf := server.Server{
				Address: c.config.Server.Address,
				Signer:  c.signatory,
			}
			srv := srvConf.New()
			srvErrCh := make(chan error)
			go func() {
				srvErrCh <- srv.ListenAndServe()
			}()

			utilityConf := server.UtilityServer{
				Address: c.config.Server.Address,
				Health:  c.signatory,
			}
			utilitySrv := utilityConf.New()
			utilityErrCh := make(chan error)
			go func() {
				utilityErrCh <- utilitySrv.ListenAndServe()
			}()

			select {
			case <-c.context.Done():
			case err := <-srvErrCh:
				return err
			case err := <-utilityErrCh:
				return err
			}

			log.Println("Shutting down...")

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()

			utilitySrv.Shutdown(ctx)
			if err := <-utilityErrCh; err != nil && err != context.Canceled && err != http.ErrServerClosed {
				return err
			}

			srv.Shutdown(ctx)
			if err := <-srvErrCh; err != nil && err != context.Canceled && err != http.ErrServerClosed {
				return err
			}

			return nil
		},
	}

	f := rootCmd.PersistentFlags()

	f.StringVarP(&configFile, "config", "c", "signatory.yaml", "Config file path")
	f.StringVar(&level, "log", "info", "Log level: [error, warn, info, debug, trace]")

	// Just an alias
	serveCmd := cobra.Command{
		Use:   "serve",
		Short: "Run a server",
		RunE:  rootCmd.RunE,
	}
	rootCmd.AddCommand(&serveCmd)
	rootCmd.AddCommand(newImportCommand(&c))
	rootCmd.AddCommand(newListCommand(&c))

	return rootCmd
}

// Execute executes root command
func Execute(ctx context.Context) error {
	return newRootCommand(ctx).Execute()
}
