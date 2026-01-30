package metrics

import (
	"strconv"
	"time"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

// SignInterceptorOptions contains SignInterceptor arguments to avoid confusion
type SignInterceptorOptions struct {
	Address    crypt.PublicKeyHash
	Vault      string
	Req        string
	ChainID    string
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
	}, []string{"address", "vault", "op", "kind", "chain_id"})

	vaultSigningHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vault_sign_request_duration_milliseconds",
		Help:    "Vaults signing requests latencies in milliseconds",
		Buckets: prometheus.ExponentialBuckets(10, 10, 5),
	}, []string{"vault", "address", "op", "chain_id"})

	vaultErrorCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vault_sign_request_error_total",
		Help: "Vaults signing requests error count",
	}, []string{"vault", "code", "chain_id"})

	signHandlerDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sign_handler_request_duration_milliseconds",
		Help:    "Total processing time for sign handler requests in milliseconds",
		Buckets: prometheus.ExponentialBuckets(10, 10, 5),
	}, []string{"address", "status"})

	signHandlerRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sign_handler_requests_total",
		Help: "Total number of sign handler requests",
	}, []string{"result", "address", "request_type"})

	SignInterceptor = InterceptorFactory(
		func(opt *SignInterceptorOptions) *prometheus.Timer {
			return prometheus.NewTimer(
				prometheus.ObserverFunc(
					func(seconds float64) {
						vaultSigningHist.WithLabelValues(opt.Vault, string(opt.Address.ToBase58()), opt.Req, opt.ChainID).Observe(seconds * 1000)
					}))
		},
		func(opt *SignInterceptorOptions, state *prometheus.Timer, err error) {
			if err != nil {
				var code string
				if val, ok := err.(errors.HTTPError); ok {
					code = strconv.FormatInt(int64(val.HTTPStatus()), 10)
				} else {
					code = "n/a"
				}
				vaultErrorCounter.WithLabelValues(opt.Vault, code, opt.ChainID).Inc()
				return // Don't record duration or increment ops counter on error
			}
			if state != nil {
				state.ObserveDuration()
			}
			for op, cnt := range opt.Stat {
				signingOpCount.WithLabelValues(string(opt.Address.ToBase58()), opt.Vault, opt.Req, op, opt.ChainID).Add(float64(cnt))
			}
		},
	)
)

func RecordSignHandlerRequest(startTime time.Time, address, status, requestType string) {
	duration := time.Since(startTime)
	signHandlerDuration.WithLabelValues(address, status).Observe(float64(duration.Milliseconds()))
	signHandlerRequestsTotal.WithLabelValues(status, address, requestType).Inc()
}

// RegisterHandler register metrics handler
func init() {
	prometheus.MustRegister(signingOpCount)
	prometheus.MustRegister(vaultSigningHist)
	prometheus.MustRegister(vaultErrorCounter)
	prometheus.MustRegister(signHandlerDuration)
	prometheus.MustRegister(signHandlerRequestsTotal)
}
