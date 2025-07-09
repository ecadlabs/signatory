package metrics

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	integrationtest "github.com/ecadlabs/signatory/new_integration_test/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Metrics struct {
	SigningOpsTotal int
	Sum             float64
	Count           int
	Error           int
}

func AssertMetricsSuccessIncremented(t *testing.T, before Metrics, after Metrics, op string) {
	assert.Greater(t, after.Count, before.Count)
	assert.Greater(t, after.Sum, before.Sum)
	// because Issue #376
	if op == "generic" {
		assert.Greater(t, after.SigningOpsTotal, before.SigningOpsTotal)
	}
	assert.Equal(t, after.Error, before.Error)
}

func AssertMetricsFailure(t *testing.T, before Metrics, after Metrics) {
	AssertMetricsSuccessUnchanged(t, before, after)
	assert.Greater(t, after.Error, before.Error)
}

func AssertMetricsSuccessUnchanged(t *testing.T, before Metrics, after Metrics) {
	assert.Equal(t, after.Count, before.Count)
	assert.Equal(t, after.Sum, before.Sum)
	assert.Equal(t, after.SigningOpsTotal, before.SigningOpsTotal)
}

// this is the most simple test of metrics. metrics validation is also added to vault and operations/kinds tests
func TestMetrics(t *testing.T) {
	metrics0 := GetMetrics(integrationtest.AlicePKH, "transaction", "generic", "File")
	_, err := integrationtest.OctezClient("transfer", "1", "from", "alice", "to", "bob")
	require.Nil(t, err)
	metrics1 := GetMetrics(integrationtest.AlicePKH, "transaction", "generic", "File")
	AssertMetricsSuccessIncremented(t, metrics0, metrics1, "generic")
}

func GetMetrics(address string, kind string, operation string, vault string) Metrics {
	metrics := Metrics{SigningOpsTotal: 0, Sum: 0, Count: 0, Error: 0}
	_, b := getBytes()
	lines := bytes.Split(b, []byte("\n"))
	for _, line := range lines {
		s := string(line)

		if strings.HasPrefix(s, "vault_sign_request_error_total") {
			if strings.Contains(s, "vault=\""+vault) {
				v := parseValue(s)
				metrics.Error, _ = strconv.Atoi(v)
			}
		}
		if strings.HasPrefix(s, "signing_ops_total") {
			if strings.Contains(s, "vault=\""+vault) &&
				strings.Contains(s, "address=\""+address) &&
				strings.Contains(s, "kind=\""+kind) {
				metrics.SigningOpsTotal, _ = strconv.Atoi(parseValue(s))
			}
		}
		if strings.HasPrefix(s, "vault_sign_request_duration_milliseconds_count") {
			if strings.Contains(s, "vault=\""+vault) &&
				strings.Contains(s, "address=\""+address) &&
				strings.Contains(s, "op=\""+operation) {
				metrics.Count, _ = strconv.Atoi(parseValue(s))
			}
		}
		if strings.HasPrefix(s, "vault_sign_request_duration_milliseconds_sum") {
			if strings.Contains(s, "vault=\""+vault) &&
				strings.Contains(s, "address=\""+address) &&
				strings.Contains(s, "op=\""+operation) {
				metrics.Sum, _ = strconv.ParseFloat(parseValue(s), 64)
			}
		}
	}
	return metrics
}

func parseValue(line string) string {
	return strings.Split(line, "} ")[1]
}

func getBytes() (int, []byte) {
	url := "http://localhost:9583/metrics"
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		panic(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return resp.StatusCode, bytes
}
