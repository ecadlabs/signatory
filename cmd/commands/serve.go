package commands

import (
	"context"
	"net/http"
	"time"

	"github.com/ecadlabs/signatory/pkg/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// NewServeCommand returns new root command
func NewServeCommand(c *Context) *cobra.Command {
	serveCmd := cobra.Command{
		Use:   "serve",
		Short: "Run a server",
		RunE: func(cmd *cobra.Command, args []string) error {
			srvConf := server.Server{
				Address: c.config.Server.Address,
				Signer:  c.signatory,
			}
			srv := srvConf.New()
			log.Printf("HTTP server is listening for connections on %s", srv.Addr)

			srvErrCh := make(chan error)
			go func() {
				srvErrCh <- srv.ListenAndServe()
			}()

			utilityConf := server.UtilityServer{
				Address: c.config.Server.UtilityAddress,
				Health:  c.signatory,
			}
			utilitySrv := utilityConf.New()
			utilityErrCh := make(chan error)
			go func() {
				utilityErrCh <- utilitySrv.ListenAndServe()
			}()

			select {
			case <-c.Context.Done():
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

	return &serveCmd
}
