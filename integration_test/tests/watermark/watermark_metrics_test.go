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

	// Block sign request at level 2, round 0
	blockSignRequest = "\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\""

	// Same level different round (double-sign attempt)
	doubleSignRequest = "\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277ae404b7528bb55c532567eb5a866e2a9e7d4e120d2627b4cfb58061756071d6f4a5630000002500000001020000000400000002000000040000000000000004ffffffff0000000400000006080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad12000000003e9dad7a000000000002\""

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

	// Attempt double-sign (same level, different round) - should be rejected
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
