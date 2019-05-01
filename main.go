package main

import (
	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/server"
	"github.com/ecadlabs/signatory/signatory"
	"github.com/ecadlabs/signatory/vault"
)

func main() {
	c := &config.Config{}
	c.Read("config.yaml")
	vault := vault.NewAzureVault(&c.Azure, nil)
	signatory := signatory.NewSignatory([]signatory.Vault{vault})

	server := server.NewServer(signatory)
	server.Serve()
}
