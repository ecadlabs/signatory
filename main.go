package main

import (
	"flag"

	"github.com/ecadlabs/signatory/config"
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

func main() {
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
	c.Read(configFile)

	vault := vault.NewAzureVault(&c.Azure, nil)
	signatory := signatory.NewSignatory([]signatory.Vault{vault}, &c.Tezos)

	server := server.NewServer(signatory, &c.Server)
	server.Serve()
}
