package metrics

import (
	"fmt"
	"testing"

	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignInterceptor_HTTPErrorCode(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode string
	}{
		{
			name:         "HTTPError with 409 status",
			err:          errors.Wrap(fmt.Errorf("watermark validation failed"), 409),
			expectedCode: "409",
		},
		{
			name:         "HTTPError with 403 status",
			err:          errors.Wrap(fmt.Errorf("forbidden"), 403),
			expectedCode: "403",
		},
		{
			name:         "HTTPError with 500 status",
			err:          errors.Wrap(fmt.Errorf("internal error"), 500),
			expectedCode: "500",
		},
		{
			name:         "plain error without HTTPError interface",
			err:          fmt.Errorf("some generic error"),
			expectedCode: "n/a",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Get error counter before
			errorCountBefore := testutil.ToFloat64(vaultErrorCounter.WithLabelValues("TestVault", tc.expectedCode, "test-chain"))

			// Create options with failing target function
			opt := &SignInterceptorOptions{
				Vault:   "TestVault",
				ChainID: "test-chain",
				Req:     "test",
				Stat:    map[string]int{},
				TargetFunc: func() (crypt.Signature, error) {
					return nil, tc.err
				},
			}

			// Call interceptor
			_, err := SignInterceptor(opt)
			require.Error(t, err)

			// Verify error counter incremented with correct code
			errorCountAfter := testutil.ToFloat64(vaultErrorCounter.WithLabelValues("TestVault", tc.expectedCode, "test-chain"))
			assert.Equal(t, errorCountBefore+1, errorCountAfter,
				"Error counter with code=%s should increment by 1", tc.expectedCode)
		})
	}
}

func TestSignInterceptor_SuccessDoesNotIncrementErrorCounter(t *testing.T) {
	vault := "SuccessVault"
	chainID := "success-chain"

	// Get error counter before for common codes
	errorCount409Before := testutil.ToFloat64(vaultErrorCounter.WithLabelValues(vault, "409", chainID))
	errorCountNABefore := testutil.ToFloat64(vaultErrorCounter.WithLabelValues(vault, "n/a", chainID))

	// Parse a valid address for the test
	addr, _ := b58.ParsePublicKeyHash([]byte("tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb"))

	opt := &SignInterceptorOptions{
		Address: addr,
		Vault:   vault,
		ChainID: chainID,
		Req:     "test",
		Stat:    map[string]int{"tx": 1},
		TargetFunc: func() (crypt.Signature, error) {
			return nil, nil // success
		},
	}

	_, err := SignInterceptor(opt)
	require.NoError(t, err)

	// Verify no error metrics were added
	errorCount409After := testutil.ToFloat64(vaultErrorCounter.WithLabelValues(vault, "409", chainID))
	errorCountNAAfter := testutil.ToFloat64(vaultErrorCounter.WithLabelValues(vault, "n/a", chainID))

	assert.Equal(t, errorCount409Before, errorCount409After,
		"Error counter with code=409 should not change on success")
	assert.Equal(t, errorCountNABefore, errorCountNAAfter,
		"Error counter with code=n/a should not change on success")
}

func TestSignInterceptor_FailureDoesNotIncrementSuccessMetrics(t *testing.T) {
	vault := "FailureTestVault"
	chainID := "failure-test-chain"

	// Get signing ops counter before
	opsCountBefore := testutil.ToFloat64(signingOpCount.WithLabelValues("", vault, "test", "tx", chainID))

	opt := &SignInterceptorOptions{
		Vault:   vault,
		ChainID: chainID,
		Req:     "test",
		Stat:    map[string]int{"tx": 1},
		TargetFunc: func() (crypt.Signature, error) {
			return nil, errors.Wrap(fmt.Errorf("test error"), 500)
		},
	}

	_, err := SignInterceptor(opt)
	require.Error(t, err)

	// Verify signing ops counter was NOT updated (Issue #306)
	opsCountAfter := testutil.ToFloat64(signingOpCount.WithLabelValues("", vault, "test", "tx", chainID))
	assert.Equal(t, opsCountBefore, opsCountAfter,
		"Signing ops counter should NOT be updated on failure")
}
