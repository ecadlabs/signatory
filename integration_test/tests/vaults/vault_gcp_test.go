package vaults_test

import (
	"os"
	"testing"

	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPVault(t *testing.T) {

	project := os.Getenv("VAULT_GCP_PROJECTID")
	location := os.Getenv("VAULT_GCP_LOCATION")
	keyring := os.Getenv("VAULT_GCP_KEYRING")
	tz3 := os.Getenv("VAULT_GCP_TZ3")
	tz3pk := os.Getenv("VAULT_GCP_TZ3_PK")
	tz3alias := "gcptz3"

	//config
	var c integrationtest.Config
	c.Read()
	var v integrationtest.VaultConfig
	v.Driver = "cloudkms"
	v.Conf = map[string]interface{}{"project": &project, "location": &location, "key_ring": &keyring}
	c.Vaults["gcp"] = &v
	var p integrationtest.TezosPolicy
	p.LogPayloads = true
	p.Allow = map[string][]string{"generic": {"reveal", "transaction"}}
	c.Tezos[tz3] = &p
	integrationtest.Backup_then_update_config(c)
	defer integrationtest.Restore_config()
	integrationtest.Restart_signatory()

	//setup
	out, err := integrationtest.OctezClient("import", "secret", "key", tz3alias, "http://signatory:6732/"+tz3)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "Tezos address added: "+tz3)
	defer integrationtest.OctezClient("forget", "address", tz3alias, "--force")

	out, err = integrationtest.OctezClient("transfer", "100", "from", "alice", "to", tz3alias, "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	//test
	out, err = integrationtest.OctezClient("transfer", "1", "from", tz3alias, "to", "alice", "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	require.Equal(t, tz3pk, integrationtest.GetPublicKey(tz3))
}
