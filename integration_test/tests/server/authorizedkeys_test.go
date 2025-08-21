package server_test

import (
	"log"
	"testing"

	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"
	"github.com/stretchr/testify/require"
)

func TestAuthorizedKeys(t *testing.T) {
	var c integrationtest.Config
	c.Read()
	c.Server.Keys = []string{integrationtest.AuthKeyPK}
	integrationtest.Backup_then_update_config(c)
	defer integrationtest.Restore_config()
	integrationtest.Restart_signatory()

	out, err := integrationtest.OctezClient("-w", "1", "transfer", "1", "from", "alice", "to", "bob", "--burn-cap", "0.06425")
	require.NotNil(t, err)
	require.Contains(t, string(out), "remote signer expects authentication signature, but no authorized key was found in the wallet")

	out, err = integrationtest.OctezClient("import", "secret", "key", "auth", integrationtest.AuthKeySK, "--force")
	defer integrationtest.OctezClient("forget", "address", "auth", "--force")
	if err != nil {
		log.Println("failed to import auth key: " + err.Error() + string(out))
	}
	require.Nil(t, err)

	out, err = integrationtest.OctezClient("-w", "1", "transfer", "1", "from", "alice", "to", "bob", "--burn-cap", "0.06425")
	require.Nil(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node.")
}
