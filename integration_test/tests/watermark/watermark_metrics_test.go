package watermark_test

import (
	"testing"

	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Baker PKH for watermark tests
	bakerPKH = "tz1WGcYos3hL7GXYXjKrMnSFdkT7FyXnFBvf"

	// Block sign request at level 2, fitness_round 0 (fields from mainnet 12180922)
	blockSignRequest = "\"11b3d79f990000000218954ac461a1b7642a78880e485b1db8da1e96f6cac6ee7dae541c7b6a8e66840b0000000069a8c3a3043c218c11c12df01faa1113bb827d7de00cc6f95993e220901ca35ff0cec5954000000021000000010200000004000000020000000000000004ffffffff0000000400000000ecbf5c99c96392b252bb846394c12c422e0cb2e050aa018dcc2a880f9c9c636858335430566f4b95401c110f33e74d3a324f83ad6003ed9d5e93ce617fa11e4400000000d7d4b0aea9d000000000\""

	// Same level and fitness round, different content (double-bake attempt; fields from mainnet 12180921)
	doubleSignRequest = "\"11b3d79f990000000218e790bc8332da94dfdf97b041d5fb918500d56e3647125732b737da8dcf1aa4040000000069a8c39d0429599f0c1222b23808083de0b51e47ea45f2cd3e916dcdd5bd5fdbc7ef5c2c3b00000021000000010200000004000000020000000000000004ffffffff00000004000000007cf2ed78325f41df290d68f691c691c976107148beae12495d946a419750ab7b03f9321cbf1a85d7701522fae4938181944dc8b746ef4e8f85260f528bfa1a2c000000005a3ca147d36b02000000\""

	backend = "file"
)

func TestWatermarkMetricsOnBlockSign(t *testing.T) {
	// Clean state
	integrationtest.Clear_watermarks()

	// Get metrics before
	metricsBefore := integrationtest.GetWatermarkMetrics(backend, "success", "block")

	// Sign a block
	code, _ := integrationtest.RequestSignature(bakerPKH, blockSignRequest)
	require.Equal(t, 200, code, "Block sign should succeed")

	// Get metrics after
	metricsAfter := integrationtest.GetWatermarkMetrics(backend, "success", "block")

	// Assert watermark operation metrics incremented
	assert.Greater(t, metricsAfter.OpsTotal, metricsBefore.OpsTotal,
		"watermark_operations_total should increment on successful block sign")
	assert.Greater(t, metricsAfter.OpDurationCount, metricsBefore.OpDurationCount,
		"watermark_operation_duration_seconds_count should increment")

	// Clean up
	integrationtest.Clear_watermarks()
}

func TestWatermarkMetricsOnRejection(t *testing.T) {
	// Clean state
	integrationtest.Clear_watermarks()

	// First sign should succeed
	code, _ := integrationtest.RequestSignature(bakerPKH, blockSignRequest)
	require.Equal(t, 200, code, "First block sign should succeed")

	// Get metrics before double-sign attempt
	metricsBeforeReject := integrationtest.GetWatermarkMetrics(backend, "rejected", "block")

	// Attempt double-bake (same level and round, different content) - should be rejected
	code, _ = integrationtest.RequestSignature(bakerPKH, doubleSignRequest)
	require.Equal(t, 409, code, "Double-sign attempt should be rejected with 409")

	// Get metrics after rejection
	metricsAfterReject := integrationtest.GetWatermarkMetrics(backend, "rejected", "block")

	// Assert rejection counter incremented
	assert.Greater(t, metricsAfterReject.OpsTotal, metricsBeforeReject.OpsTotal,
		"watermark_operations_total with result=rejected should increment on double-sign rejection")

	// Clean up
	integrationtest.Clear_watermarks()
}

func TestWatermarkIOMetrics(t *testing.T) {
	// Clean state
	integrationtest.Clear_watermarks()

	// Get IO metrics before
	ioMetricsBefore := integrationtest.GetWatermarkMetrics(backend, "success", "")

	// Sign a block - this triggers read and write operations
	code, _ := integrationtest.RequestSignature(bakerPKH, blockSignRequest)
	require.Equal(t, 200, code, "Block sign should succeed")

	// Get IO metrics after
	ioMetricsAfter := integrationtest.GetWatermarkMetrics(backend, "success", "")

	// Assert IO operations were tracked
	assert.Greater(t, ioMetricsAfter.IOOpsTotal, ioMetricsBefore.IOOpsTotal,
		"watermark_io_operations_total should increment on watermark file operations")
	assert.Greater(t, ioMetricsAfter.IOLatencyCount, ioMetricsBefore.IOLatencyCount,
		"watermark_io_latency_seconds_count should increment")

	// Clean up
	integrationtest.Clear_watermarks()
}
