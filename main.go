package main

import (
	"flag"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/server"
	"github.com/ecadlabs/signatory/signatory"
	"github.com/ecadlabs/signatory/vault"

	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.DebugLevel)

	var configFile string
	flag.StringVar(&configFile, "config", "signatory.yaml", "Config file path")

	flag.Parse()

	c := &config.Config{}
	c.Read(configFile)

	vault := vault.NewAzureVault(&c.Azure, nil)
	signatory := signatory.NewSignatory([]signatory.Vault{vault})

	server := server.NewServer(signatory)
	server.Serve()
}
