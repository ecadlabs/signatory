package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/metrics"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/watermark"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

const (
	defaultPort = 80
	// Registered here https://github.com/prometheus/prometheus/wiki/Default-port-allocations
	defaultUtilityPort = 9583
)

func createVaults(c *config.Config) ([]signatory.Vault, []signatory.Importer, []server.Health, error) {
	vaults := []signatory.Vault{}
	importers := []signatory.Importer{}
	healths := []server.Health{}

	for _, azCfg := range c.Azure {
		azureVault := vault.NewAzureVault(*azCfg, nil)
		vaults = append(vaults, azureVault)
		healths = append(healths, azureVault)
		importers = append(importers, azureVault)
	}

	for _, yubiCfg := range c.Yubi {
		yubiVault, err := vault.NewYubi(*yubiCfg)
		if err != nil {
			return nil, nil, nil, err
		}
		vaults = append(vaults, yubiVault)
		healths = append(healths, yubiVault)
	}

	for _, kmsCfg := range c.CloudKMS {
		kmsVault, err := vault.NewCloudKMSVault(context.TODO(), kmsCfg)
		if err != nil {
			return nil, nil, nil, err
		}
		vaults = append(vaults, kmsVault)
		importers = append(importers, kmsVault)
	}

	return vaults, importers, healths, nil
}

func doImport(s *signatory.Signatory, importers []signatory.Importer) {
	if len(flag.Args()) != 3 {
		flag.Usage()
		return
	}

	pk := flag.Arg(0)
	sk := flag.Arg(1)
	v := flag.Arg(2)

	for _, vault := range importers {
		if vault.Name() == v {
			_, err := s.Import(pk, sk, vault)
			if err != nil {
				log.Error(err)
				return
			}
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
		Tezos: make(config.TezosConfig),
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

	s := signatory.NewSignatory(vaults, c.Tezos, metrics.Interceptor, watermark.NewMemory(), nil)

	srv := server.NewServer(s, &c.Server, nil)
	utilityServer := server.NewUtilityServer(&c.Server, healths)

	if importKey {
		doImport(s, importers)
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
		log.Error("No keys discovered in Key Vault(s), exiting..")
		os.Exit(1)
	}

	log.Info("Keys discovered in Key Vault:")
	var allowedKeyCount int
	for _, key := range pubKeys {
		l := log.WithField(signatory.LogPKH, key)

		vault, _, err := s.GetCachedPublicKey(ctx, key)
		if err != nil {
			l.Error(err)
			continue
		}

		logfields := log.Fields{signatory.LogVault: vault.Name()}
		if n, ok := vault.(signatory.VaultNamer); ok {
			logfields[signatory.LogVaultName] = n.VaultName()
		}
		l = l.WithFields(logfields)

		if s.IsAllowed(key) {
			allowedKeyCount++
			l.Info("Key configured, ready for use")
		} else {
			l.Infof("Key found in vault but not configured in %s", configFile)
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
