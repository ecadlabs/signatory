package metrics

import (
	"testing"

	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	metrics0 := integrationtest.GetMetrics(integrationtest.AlicePKH, "transaction", "generic", "File", "")
	_, err := integrationtest.OctezClient("transfer", "1", "from", "alice", "to", "bob")
	require.Nil(t, err)
	metrics1 := integrationtest.GetMetrics(integrationtest.AlicePKH, "transaction", "generic", "File", "")
	integrationtest.AssertMetricsSuccessIncremented(t, metrics0, metrics1)
}

func TestMetricsChainIDLabel(t *testing.T) {
	_, err := integrationtest.OctezClient("transfer", "1", "from", "alice", "to", "bob")
	require.Nil(t, err)

	t.Run("signing_ops_total has chain_id label", func(t *testing.T) {
		assert.True(t, integrationtest.VerifyChainIDLabelPresent("signing_ops_total"),
			"signing_ops_total should have chain_id label")
	})

	t.Run("vault_sign_request_duration_milliseconds has chain_id label", func(t *testing.T) {
		assert.True(t, integrationtest.VerifyChainIDLabelPresent("vault_sign_request_duration_milliseconds"),
			"vault_sign_request_duration_milliseconds should have chain_id label")
	})

	t.Run("generic operations have empty chain_id", func(t *testing.T) {
		chainID := integrationtest.ExtractChainIDFromMetrics(integrationtest.AlicePKH, "generic", "File")
		assert.Empty(t, chainID, "generic operations should have empty chain_id")
	})
}
