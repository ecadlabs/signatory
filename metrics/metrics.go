package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var signingOpCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "signing_ops_total",
	Help: "Total number of signing operations completed.",
}, []string{"address", "vault", "kind"})

var Handler http.Handler

// RegisterHandler register metrics handler
func init() {
	prometheus.MustRegister(signingOpCount)
	prometheus.MustRegister(vaultSigningSummary)
	Handler = promhttp.Handler()
}

// IncNewSigningOp register a new signing operation with vault
func IncNewSigningOp(address string, vault string, kind string) {
	signingOpCount.WithLabelValues(address, vault, kind).Inc()
}
