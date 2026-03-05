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

func TestSignHandlerMetrics(t *testing.T) {
	t.Run("increments on success", func(t *testing.T) {
		before := integrationtest.GetHandlerMetrics(integrationtest.AlicePKH, "200")
		_, err := integrationtest.OctezClient("transfer", "1", "from", "alice", "to", "bob")
		require.Nil(t, err)
		after := integrationtest.GetHandlerMetrics(integrationtest.AlicePKH, "200")

		assert.Greater(t, after.RequestsTotal, before.RequestsTotal,
			"sign_handler_requests_total{status=200} should increment after successful sign")
		assert.Greater(t, after.DurationCount, before.DurationCount,
			"sign_handler_request_duration_milliseconds_count{status=200} should increment")
	})

	t.Run("records rejection with error status", func(t *testing.T) {
		ok200 := integrationtest.GetHandlerMetrics(integrationtest.AlicePKH, "200")
		err403 := integrationtest.GetHandlerMetrics(integrationtest.AlicePKH, "403")
		// Delegation is not in alice's allow policy, signatory returns 403
		_, _ = integrationtest.OctezClient("register", "key", "alice", "as", "delegate")
		ok200After := integrationtest.GetHandlerMetrics(integrationtest.AlicePKH, "200")
		err403After := integrationtest.GetHandlerMetrics(integrationtest.AlicePKH, "403")

		assert.Equal(t, ok200.RequestsTotal, ok200After.RequestsTotal,
			"sign_handler_requests_total{status=200} should not increment on rejection")
		assert.Greater(t, err403After.RequestsTotal, err403.RequestsTotal,
			"sign_handler_requests_total{status=403} should increment on policy rejection")
		assert.Greater(t, err403After.DurationCount, err403.DurationCount,
			"sign_handler_request_duration_milliseconds_count{status=403} should increment on policy rejection")
	})
}
