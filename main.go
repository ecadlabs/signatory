package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

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

func createVaults(c *config.Config) ([]signatory.Vault, []signatory.Importer, []server.Health, error) {
	vaults := []signatory.Vault{}
	importers := []signatory.Importer{}
	healths := []server.Health{}
	for _, azCfg := range c.Azure {
		azureVault := vault.NewAzureVault(azCfg, nil)
		vaults = append(vaults, azureVault)
		healths = append(healths, azureVault)
		importers = append(importers, azureVault)
	}

	for _, yubiCfg := range c.Yubi {
		yubiVault, err := vault.NewYubi(yubiCfg)
		if err != nil {
			return nil, nil, nil, err
		}
		vaults = append(vaults, yubiVault)
		healths = append(healths, yubiVault)
	}

	for i := range vaults {
		vault := vaults[i]
		wrapped := metrics.Wrap(vault)
		vaults[i] = wrapped
	}

	return vaults, importers, healths, nil
}

func doImport(importers []signatory.Importer) {
	if len(flag.Args()) != 3 {
		flag.Usage()
		return
	}

	pk := flag.Arg(0)
	sk := flag.Arg(1)
	v := flag.Arg(2)

	for _, vault := range importers {
		if vault.Name() == v {
			importedKey, err := signatory.Import(pk, sk, vault)
			if err != nil {
				log.Error(err)
				return
			}

			log.Infof("%s, %s", importedKey.Hash, importedKey.KeyID)

			return
		}
	}
	log.Fatalf("Unable to find vault: %s", v)
}

func main() {
	done := make(chan os.Signal)
	errChan := make(chan error)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	var configFile string
	var logLevelFlag string
	var importKey bool
	flag.StringVar(&configFile, "config", "signatory.yaml", "Config file path")
	flag.StringVar(&logLevelFlag, "log-level", "info", "Log level")
	flag.BoolVar(&importKey, "import", false, "import [public key] [secret key] [vault]")
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

	if valid, msg := c.Validate(); !valid {
		log.Fatal(msg)
	}

	vaults, importers, healths, err := createVaults(c)
	if err != nil {
		log.Fatal(err)
	}

	s := signatory.NewSignatory(vaults, &c.Tezos, metrics.IncNewSigningOp, watermark.NewMemory())

	srv := server.NewServer(s, &c.Server)
	utilityServer := server.NewUtilityServer(&c.Server, healths)

	if importKey {
		doImport(importers)
		return
	}

	log.Info("Discovering supported keys from vault(s)...")

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*10)
	defer cancelFunc()

	pubKeys, err := s.ListPublicKeyHash(ctx)

	if err != nil {
		log.Fatal(err)
	}
	if len(pubKeys) == 0 {
		log.Error("No keys discovered in Key Valut(s), exiting..")
		os.Exit(1)
	}

	log.Info("Keys discovered in Key Vault:\n\n")
	var allowedKeyCount int
	for _, key := range pubKeys {
		if s.IsAllowed(key) {
			allowedKeyCount++
			log.Infof("%s (Configured, ready for use)", key)
		} else {
			log.Infof("%s (Found in vault, not configured for use in %s)", key, configFile)
		}
	}
	if allowedKeyCount == 0 {
		log.Errorf("No keys configured for signing. To allow a key add it to the tezos.keys list in %s ", configFile)
		os.Exit(1)
	}

	fmt.Println()

	log.Infof("Only Allowed keys can sign. To allow a key add it to the tezos.keys list in %s", configFile)

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
