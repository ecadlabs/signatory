package metrics

import (
	"strconv"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/prometheus/client_golang/prometheus"
)

type HttpError interface {
	Code() int
}

// SignInterceptorOptions contains SignInterceptor arguments to avoid confusion
type SignInterceptorOptions struct {
	Address    crypt.PublicKeyHash
	Vault      string
	Req        string
	Stat       map[string]int
	TargetFunc func() (crypt.Signature, error)
}

func (o SignInterceptorOptions) GetTargetFunc() func() (crypt.Signature, error) {
	return o.TargetFunc
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

	vaultErrorCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vault_sign_request_error_total",
		Help: "Vaults signing requests error count",
	}, []string{"vault", "code"})

	SignInterceptor = InterceptorFactory(
		func(opt SignInterceptorOptions) *prometheus.Timer {
			return prometheus.NewTimer(
				prometheus.ObserverFunc(
					func(seconds float64) {
						vaultSigningHist.WithLabelValues(opt.Vault, string(opt.Address.ToBase58()), opt.Req).Observe(seconds * 1000)
					}))
		},
		func(opt SignInterceptorOptions, state *prometheus.Timer, err error) {
			if state != nil {
				state.ObserveDuration()
			}
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
				signingOpCount.WithLabelValues(string(opt.Address.ToBase58()), opt.Vault, opt.Req, op).Add(float64(cnt))
			}
		},
	)
)

// RegisterHandler register metrics handler
func init() {
	prometheus.MustRegister(signingOpCount)
	prometheus.MustRegister(vaultSigningHist)
	prometheus.MustRegister(vaultErrorCounter)
}
