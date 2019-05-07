package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var signingOpCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "signing_ops_total",
	Help: "Total number of signing operations completed.",
}, []string{"address", "vault", "algorithm", "kind"})

// RegisterHandler register metrics handler
func RegisterHandler() {
	http.Handle("/metrics", promhttp.Handler())
	prometheus.MustRegister(signingOpCount)
}

// IncNewSigningOp register a new signing operation with vault
func IncNewSigningOp(address string, vault string, algorithm string, kind string) {
  signingOpCount.WithLabelValues(address, vault, algorithm, kind).Inc()
}
