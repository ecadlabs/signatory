package vaults_test

import (
	"testing"

	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"

	"github.com/stretchr/testify/require"
)

func TestNitroEnclaveVault(t *testing.T) {
	out, err := integrationtest.OctezClient("-w", "1", "transfer", "1", "from", "nitro", "to", "alice", "--burn-cap", "0.06425")
	require.NoError(t, err)
	require.Contains(t, string(out), "Operation successfully injected in the node")
}
