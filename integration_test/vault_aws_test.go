package integrationtest

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSVault(t *testing.T) {

	tz2 := os.Getenv("VAULT_AWS_TZ2")
	tz3 := os.Getenv("VAULT_AWS_TZ3")
	tz3pk := os.Getenv("VAULT_AWS_TZ3_PK")
	user := os.Getenv("VAULT_AWS_USER")
	key := os.Getenv("VAULT_AWS_KEY")
	secret := os.Getenv("VAULT_AWS_SECRET")
	region := os.Getenv("VAULT_AWS_REGION")

	tz2alias := "awstz2"
	tz3alias := "awstz3"

	//config
	var c Config
	c.Read()
	var v VaultConfig
	v.Driver = "awskms"
	v.Conf = map[string]interface{}{"user_name": &user, "access_key_id": &key, "secret_access_key": &secret, "region": &region}
	c.Vaults["aws"] = &v
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
	//TODO: resolve issue #364 and enable the tz2 test
	//out, err = OctezClient("transfer", "1", "from", tz2alias, "to", "alice", "--burn-cap", "0.06425")
	//assert.NoError(t, err)
	//require.Contains(t, string(out), "Operation successfully injected in the node")

	out, err = OctezClient("transfer", "1", "from", tz3alias, "to", "alice", "--burn-cap", "0.06425")
	assert.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")

	require.Equal(t, tz3pk, GetPublicKey(tz3))
}
