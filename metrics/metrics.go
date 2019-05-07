package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RegisterHandler register metrics handler
func RegisterHandler() {
	http.Handle("/metrics", promhttp.Handler())
}
