package azure

import (
	"context"
	"testing"

	"github.com/davecgh/go-spew/spew"

	"github.com/ecadlabs/signatory/pkg/vault/azure/auth"
	log "github.com/sirupsen/logrus"
)

func TestAzure(t *testing.T) {
	log.SetLevel(log.TraceLevel)

	c := Config{
		Config: auth.Config{
			Tenant:                  "50c46f11-1d0a-4c56-b468-1bcb03a8f69e",
			ClientID:                "b7ddefbb-fcac-4068-813b-b3450c36b9a7",
			ClientPKCS12Certificate: "/Users/asphyx/Projects/signatory/service-principal.pfx",
		},
		Vault: "https://signatory.vault.azure.net/",
	}

	v, err := NewVault(context.Background(), &c)
	if err != nil {
		t.Fatal(err)
	}

	l, err := v.ListPublicKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	spew.Dump(l)
}
