package metrics

import (
	"strconv"

	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type HttpError interface {
	Code() int
}

// Handler is an alias for default Prometheus HTTP handler
var Handler = promhttp.Handler()

// RegisterHandler register metrics handler
func init() {
	prometheus.MustRegister(signingOpCount)
	prometheus.MustRegister(vaultSigningHist)
	prometheus.MustRegister(vaultErrorCounter)
}

var (
	signingOpCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "signing_ops_total",
		Help: "Total number of signing operations completed.",
	}, []string{"address", "vault", "op", "kind"})

	vaultSigningHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vault_sign_request_duration_milliseconds",
		Help:    "Vaults signing requests latencies in milliseconds",
		Buckets: prometheus.ExponentialBuckets(10, 10, 5),
	}, []string{"vault", "address", "op"})

	vaultErrorCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vault_sign_request_error_total",
			Help: "Vaults signing requests error count",
		}, []string{"vault", "code"})
)

// Interceptor function collects sign operation metrics
func Interceptor(opt *signatory.SignInterceptorOptions, sign func() error) error {
	timer := prometheus.NewTimer(
		prometheus.ObserverFunc(
			func(seconds float64) {
				vaultSigningHist.WithLabelValues(opt.Vault, opt.Address, opt.Req).Observe(seconds * 1000)
			}))
	err := sign()
	timer.ObserveDuration()

	if err != nil {
		var code string
		if val, ok := err.(HttpError); ok {
			code = strconv.FormatInt(int64(val.Code()), 10)
		} else {
			code = "n/a"
		}
		vaultErrorCounter.WithLabelValues(opt.Vault, code).Inc()
	}

	for op, cnt := range opt.Stat {
		signingOpCount.WithLabelValues(opt.Address, opt.Vault, opt.Req, op).Add(float64(cnt))
	}

	return err
}
