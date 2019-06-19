package metrics

import (
	"fmt"
	"time"

	"github.com/ecadlabs/signatory/signatory"
	"github.com/prometheus/client_golang/prometheus"
)

type HttpError interface {
	Code() int
}

var vaultSigningSummary = prometheus.NewSummaryVec(
	prometheus.SummaryOpts{
		Name: "vault_sign_request_duration_microseconds",
		Help: "Vaults signing requests latencies in microseconds",
	}, []string{"vault"})

var vaultErrorCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vault_sign_request_error_total",
		Help: "Vaults signing requests error count",
	}, []string{"vault", "code"})

type metricVault struct {
	vault signatory.Vault
}

func (v *metricVault) GetPublicKey(keyHash string) (signatory.StoredKey, error) {
	return v.vault.GetPublicKey(keyHash)
}
func (v *metricVault) ListPublicKeys() ([]signatory.StoredKey, error) { return v.vault.ListPublicKeys() }
func (v *metricVault) Sign(digest []byte, key signatory.StoredKey) ([]byte, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(val float64) {
		us := val * float64(time.Microsecond)
		vaultSigningSummary.WithLabelValues(v.vault.Name()).Observe(us)
	}))
	defer timer.ObserveDuration()

	result, err := v.vault.Sign(digest, key)

	if err != nil {
		if val, ok := err.(HttpError); ok {
			vaultErrorCounter.WithLabelValues(v.vault.Name(), fmt.Sprintf("%d", val.Code())).Inc()
		} else {
			vaultErrorCounter.WithLabelValues(v.vault.Name(), "n/a").Inc()
		}
	}

	return result, err
}
func (v *metricVault) Name() string { return v.vault.Name() }

// Wrap decorate a vault with prometheus metrics
func Wrap(vault signatory.Vault) signatory.Vault {
	return &metricVault{vault: vault}
}
