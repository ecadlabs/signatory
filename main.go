package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/metrics"
	"github.com/ecadlabs/signatory/server"
	"github.com/ecadlabs/signatory/signatory"
	"github.com/ecadlabs/signatory/tezos"
	"github.com/ecadlabs/signatory/vault"

	log "github.com/sirupsen/logrus"
)

const (
	defaultPort = 80
)

var (
	defaultOperations = []string{tezos.OpBlock, tezos.OpEndorsement}
)

func createVaults(c *config.Config) []signatory.Vault {
	azureVault := vault.NewAzureVault(&c.Azure, nil)
	vaults := []signatory.Vault{azureVault}
	for i := range vaults {
		vault := vaults[i]
		wrapped := metrics.Wrap(vault)
		vaults[i] = wrapped
	}

	return vaults
}

func main() {
	done := make(chan os.Signal)
	errChan := make(chan error)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	log.SetLevel(log.DebugLevel)

	var configFile string
	flag.StringVar(&configFile, "config", "signatory.yaml", "Config file path")

	flag.Parse()

	c := &config.Config{
		Server: config.ServerConfig{
			Port: defaultPort,
		},
		Tezos: config.TezosConfig{
			AllowedOperations: defaultOperations,
		},
	}
	err := c.Read(configFile)
	if err != nil {
		log.Fatal(err)
	}

	signatory := signatory.NewSignatory(createVaults(c), &c.Tezos, metrics.IncNewSigningOp)

	srv := server.NewServer(signatory, &c.Server)
	utilityServer := server.NewUtilityServer(&c.Server)

	go func() {
		err := utilityServer.Serve()
		if err != nil {
			errChan <- err
		}
	}()

	log.Infof("Utility Server listening on port: %d", c.Server.Port+1)

	go func() {
		err := srv.Serve()
		if err != nil {
			errChan <- err
		}
	}()

	log.Infof("Server listening on port: %d", c.Server.Port)

	shutdown := func() {
		log.Info("Shutting down...")
		ctx := context.Background()
		utilityServer.ShutdownAfter(ctx, func() {
			srv.Shutdown(ctx)
		})
	}

	select {
	case <-done:
		shutdown()
		log.Info("Signatory shutted down gracefully")
		return
	case err := <-errChan:
		shutdown()
		log.Fatal(err)
	}
}
