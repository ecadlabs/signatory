package integrationtest

import (
	"os"
	"testing"

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
	var c Config
	c.Read()
	var v VaultConfig
	v.Driver = "cloudkms"
	v.Conf = map[string]*string{"project": &project, "location": &location, "key_ring": &keyring}
	c.Vaults["gcp"] = &v
	var p TezosPolicy
	p.LogPayloads = true
	p.Allow = map[string][]string{"generic": {"reveal", "transaction"}}
	c.Tezos[tz3] = &p
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()

	//setup
	out, err := OctezClient("import", "secret", "key", tz3alias, "http://signatory:6732/"+tz3)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "Tezos address added: "+tz3)
	defer OctezClient("forget", "address", tz3alias, "--force")

	out, err = OctezClient("transfer", "100", "from", "alice", "to", tz3alias, "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	//test
	out, err = OctezClient("transfer", "1", "from", tz3alias, "to", "alice", "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	require.Equal(t, tz3pk, GetPublicKey(tz3))
}
