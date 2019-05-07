package metrics

import (
	"time"

	"github.com/ecadlabs/signatory/signatory"
	"github.com/prometheus/client_golang/prometheus"
)

var vaultSigningSummary = prometheus.NewSummaryVec(
	prometheus.SummaryOpts{
		Name: "vault_sign_request_duration_microseconds",
		Help: "Vaults signing requests latencies in microseconds",
	}, []string{"vault"})

type metricVault struct {
	vault signatory.Vault
}

func (v *metricVault) Contains(keyHash string) bool { return v.vault.Contains(keyHash) }
func (v *metricVault) GetPublicKey(keyHash string) (signatory.PublicKey, error) {
	return v.vault.GetPublicKey(keyHash)
}
func (v *metricVault) ListPublicKeys() ([]signatory.PublicKey, error) { return v.vault.ListPublicKeys() }
func (v *metricVault) Sign(digest []byte, key string, alg string) ([]byte, error) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(val float64) {
		us := val * float64(time.Microsecond)
		vaultSigningSummary.WithLabelValues(v.vault.Name()).Observe(us)
	}))
	defer timer.ObserveDuration()
	return v.vault.Sign(digest, key, alg)
}
func (v *metricVault) Import(jwk *signatory.JWK) (string, error) { return v.vault.Import(jwk) }
func (v *metricVault) Name() string                              { return v.vault.Name() }

// Wrap decorate a vault with prometheus metrics
func Wrap(vault signatory.Vault) signatory.Vault {
	return &metricVault{vault: vault}
}
