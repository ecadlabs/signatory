package metrics

import (
	"testing"

	integrationtest "github.com/ecadlabs/signatory/new_integration_test/tests"
	"github.com/stretchr/testify/require"
)

// this is the most simple test of metrics. metrics validation is also added to vault and operations/kinds tests
func TestMetrics(t *testing.T) {
	metrics0 := integrationtest.GetMetrics(integrationtest.AlicePKH, "transaction", "generic", "File")
	_, err := integrationtest.OctezClient("transfer", "1", "from", "alice", "to", "bob")
	require.Nil(t, err)
	metrics1 := integrationtest.GetMetrics(integrationtest.AlicePKH, "transaction", "generic", "File")
	integrationtest.AssertMetricsSuccessIncremented(t, metrics0, metrics1, "generic")
}
