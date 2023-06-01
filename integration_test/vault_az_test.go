package integrationtest

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	tz2alias := "aztz2"
	tz3alias := "aztz3"

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
	defer restore_config()
	restart_signatory()

	//setup
	out, err := OctezClient("import", "secret", "key", tz2alias, "http://signatory:6732/"+tz2)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "Tezos address added: "+tz2)
	defer OctezClient("forget", "address", tz2alias, "--force")
	out, err = OctezClient("import", "secret", "key", tz3alias, "http://signatory:6732/"+tz3)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "Tezos address added: "+tz3)
	defer OctezClient("forget", "address", tz3alias, "--force")

	out, err = OctezClient("transfer", "100", "from", "alice", "to", tz2alias, "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
	out, err = OctezClient("transfer", "100", "from", "alice", "to", tz3alias, "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	//test
	/* the tz2 key produces invalid signature 50% of the time from octez-client perspective
	out, err = OctezClient("transfer", "1", "from", tz2alias, "to", "alice", "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
	*/
	out, err = OctezClient("transfer", "1", "from", tz3alias, "to", "alice", "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
}
