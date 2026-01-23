package tests

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type Metrics struct {
	SigningOpsTotal int
	Sum             float64
	Count           int
	Error           int
}

func GetMetrics(address string, kind string, operation string, vault string, chainID string) Metrics {
	metrics := Metrics{SigningOpsTotal: 0, Sum: 0, Count: 0, Error: 0}
	_, b := getBytes()
	lines := bytes.Split(b, []byte("\n"))
	for _, line := range lines {
		s := string(line)

		if strings.HasPrefix(s, "vault_sign_request_error_total") {
			if strings.Contains(s, "vault=\""+vault) &&
				(chainID == "" || strings.Contains(s, "chain_id=\""+chainID)) {
				v := parseValue(s)
				metrics.Error, _ = strconv.Atoi(v)
			}
		}
		if strings.HasPrefix(s, "signing_ops_total") {
			if strings.Contains(s, "vault=\""+vault) &&
				strings.Contains(s, "address=\""+address) &&
				strings.Contains(s, "kind=\""+kind) &&
				(chainID == "" || strings.Contains(s, "chain_id=\""+chainID)) {
				metrics.SigningOpsTotal, _ = strconv.Atoi(parseValue(s))
			}
		}
		if strings.HasPrefix(s, "vault_sign_request_duration_milliseconds_count") {
			if strings.Contains(s, "vault=\""+vault) &&
				strings.Contains(s, "address=\""+address) &&
				strings.Contains(s, "op=\""+operation) &&
				(chainID == "" || strings.Contains(s, "chain_id=\""+chainID)) {
				metrics.Count, _ = strconv.Atoi(parseValue(s))
			}
		}
		if strings.HasPrefix(s, "vault_sign_request_duration_milliseconds_sum") {
			if strings.Contains(s, "vault=\""+vault) &&
				strings.Contains(s, "address=\""+address) &&
				strings.Contains(s, "op=\""+operation) &&
				(chainID == "" || strings.Contains(s, "chain_id=\""+chainID)) {
				metrics.Sum, _ = strconv.ParseFloat(parseValue(s), 64)
			}
		}
	}
	return metrics
}

func AssertMetricsSuccessIncremented(t *testing.T, before Metrics, after Metrics) {
	assert.Greater(t, after.Count, before.Count)
	assert.Greater(t, after.Sum, before.Sum)
	assert.Greater(t, after.SigningOpsTotal, before.SigningOpsTotal)
	assert.Equal(t, after.Error, before.Error)
}

func AssertMetricsUnchanged(t *testing.T, before Metrics, after Metrics) {
	assert.Equal(t, after.Count, before.Count)
	assert.Equal(t, after.Sum, before.Sum)
	assert.Equal(t, after.SigningOpsTotal, before.SigningOpsTotal)
	assert.Equal(t, after.Error, before.Error)
}

func parseValue(line string) string {
	return strings.Split(line, "} ")[1]
}

func VerifyChainIDLabelPresent(metricName string) bool {
	_, b := getBytes()
	lines := bytes.Split(b, []byte("\n"))
	for _, line := range lines {
		s := string(line)
		if strings.HasPrefix(s, metricName) && strings.Contains(s, "chain_id=\"") {
			return true
		}
	}
	return false
}

func ExtractChainIDFromMetrics(address string, operation string, vault string) string {
	_, b := getBytes()
	lines := bytes.Split(b, []byte("\n"))
	for _, line := range lines {
		s := string(line)
		if strings.HasPrefix(s, "vault_sign_request_duration_milliseconds_count") &&
			strings.Contains(s, "vault=\""+vault) &&
			strings.Contains(s, "address=\""+address) &&
			strings.Contains(s, "op=\""+operation) {
			start := strings.Index(s, "chain_id=\"")
			if start == -1 {
				return ""
			}
			start += len("chain_id=\"")
			end := strings.Index(s[start:], "\"")
			if end == -1 {
				return ""
			}
			return s[start : start+end]
		}
	}
	return ""
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
