package integrationtest

import (
	"os"
	"testing"
)

func TestAZVault(t *testing.T) {

	spkey := "/etc/service-principal.key"

	thumb := os.Getenv("VAULT_AZ_CLIENTCERTTHUMB")
	clientid := os.Getenv("VAULT_AZ_CLIENTID")
	resgroup := os.Getenv("VAULT_AZ_RESGROUP")
	subid := os.Getenv("VAULT_AZ_SUBID")
	tenantid := os.Getenv("VAULT_AZ_TENANTID")
	vault := os.Getenv("VAULT_AZ_VAULT")

	tz2 := os.Getenv("VAULT_AZ_TZ2")
	tz3 := os.Getenv("VAULT_AZ_TZ3")

	//config
	var c Config
	c.Read()
	var v VaultConfig
	v.Driver = "azure"
	v.Conf = map[string]*string{"vault": &vault, "tenant_id": &tenantid, "client_id": &clientid, "client_private_key": &spkey, "client_certificate_thumbprint": &thumb, "subscription_id": &subid, "resource_group": &resgroup}
	c.Vaults["azure"] = &v
	var p TezosPolicy
	p.LogPayloads = true
	p.Allow = map[string][]string{"generic": {"reveal", "transaction"}}
	c.Tezos[tz2] = &p
	c.Tezos[tz3] = &p
	backup_then_update_config(c)

}
