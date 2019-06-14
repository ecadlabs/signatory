package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/metrics"
	"github.com/ecadlabs/signatory/server"
	"github.com/ecadlabs/signatory/signatory"
	"github.com/ecadlabs/signatory/tezos"
	"github.com/ecadlabs/signatory/vault"
	"github.com/ecadlabs/signatory/watermark"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

const (
	defaultPort = 80
	// Registered here https://github.com/prometheus/prometheus/wiki/Default-port-allocations
	defaultUtilityPort = 9583
)

var (
	defaultOperations = []string{tezos.OpBlock, tezos.OpEndorsement}
	defaultKinds      = []string{}
)

func createVaults(c *config.Config) ([]signatory.Vault, []server.Health) {
	vaults := []signatory.Vault{}
	healths := []server.Health{}
	for _, azCfg := range c.Azure {
		azureVault := vault.NewAzureVault(azCfg, nil)
		vaults = append(vaults, azureVault)
		healths = append(healths, azureVault)
	}
	for i := range vaults {
		vault := vaults[i]
		wrapped := metrics.Wrap(vault)
		vaults[i] = wrapped
	}

	return vaults, healths
}

func main() {
	done := make(chan os.Signal)
	errChan := make(chan error)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	var configFile string
	var logLevelFlag string
	flag.StringVar(&configFile, "config", "signatory.yaml", "Config file path")
	flag.StringVar(&logLevelFlag, "log-level", "info", "Log level")
	flag.Parse()

	if lvl, err := logrus.ParseLevel(logLevelFlag); err == nil {
		log.SetLevel(lvl)
	} else {
		log.Fatal(err.Error())
	}

	c := &config.Config{
		Server: config.ServerConfig{
			Port:        defaultPort,
			UtilityPort: defaultUtilityPort,
		},
		Tezos: config.TezosConfig{
			AllowedOperations: defaultOperations,
			AllowedKinds:      defaultKinds,
		},
	}
	err := c.Read(configFile)
	if err != nil {
		log.Fatal(err)
	}

	vaults, healths := createVaults(c)
	signatory := signatory.NewSignatory(vaults, &c.Tezos, metrics.IncNewSigningOp, watermark.NewMemory())

	srv := server.NewServer(signatory, &c.Server)
	utilityServer := server.NewUtilityServer(&c.Server, healths)

	log.Info("Detecting supported keys...")
	pubKeys, err := signatory.ListPublicKeyHash()

	if err != nil {
		panic("Unable to reach vault")
	}

	log.Info("Supported keys:\n\n")
	for _, key := range pubKeys {
		if signatory.IsAllowed(key) {
			log.Infof("%s (Whitelisted) \n", key)
		} else {
			log.Infof("%s\n", key)
		}
	}

	fmt.Println()

	log.Infof("Only whitelisted keys can sign. \n\n")

	go func() {
		err := utilityServer.Serve()
		if err != nil {
			errChan <- err
		}
	}()

	log.Infof("Utility Server listening on port: %d", c.Server.UtilityPort)

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
		log.Info("Signatory shut down gracefully")
		return
	case err := <-errChan:
		shutdown()
		log.Fatal(err)
	}
}
