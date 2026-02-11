package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type WatermarkInterceptorOptions struct {
	Backend     string
	RequestType string
	TargetFunc  func() (bool, error)
}

func (o WatermarkInterceptorOptions) GetTargetFunc() func() (bool, error) {
	return o.TargetFunc
}

type IOInterceptorOptions[R any] struct {
	Backend    string
	Operation  string // "read", "write", "create"
	TableName  string // table/collection name for databases, "" for file backend
	TargetFunc func() (R, error)
}

func (o IOInterceptorOptions[R]) GetTargetFunc() func() (R, error) {
	return o.TargetFunc
}

var (
	// Core watermark metrics for all backends
	watermarkOpsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "watermark_operations_total",
		Help: "Total number of watermark operations",
	}, []string{"result", "backend", "request_type"})

	watermarkOpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "watermark_operation_duration_seconds",
		Help:    "Watermark operation duration in seconds",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
	}, []string{"backend"})

	watermarkIOOpsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "watermark_io_operations_total",
		Help: "Total number of watermark backend I/O operations",
	}, []string{"backend", "operation", "table_name", "result"})

	watermarkIOLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "watermark_io_latency_seconds",
		Help:    "Watermark backend I/O latency in seconds",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 14), // 0.1ms to ~1.6s
	}, []string{"backend", "operation", "table_name"})

	watermarkIOErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "watermark_io_errors_total",
		Help: "Total number of watermark backend I/O errors",
	}, []string{"backend", "error_type", "table_name", "operation"})

	WatermarkInterceptor = InterceptorFactory(
		func(opt *WatermarkInterceptorOptions) *prometheus.Timer {
			return prometheus.NewTimer(watermarkOpDuration.WithLabelValues(opt.Backend))
		},
		func(opt *WatermarkInterceptorOptions, state *prometheus.Timer, err error) {
			if state != nil {
				state.ObserveDuration()
			}
			result := "success"
			if err != nil {
				result = "rejected"
			}
			watermarkOpsTotal.WithLabelValues(result, opt.Backend, opt.RequestType).Inc()
		},
	)
)

func IOInterceptor[R any](opt *IOInterceptorOptions[R]) (R, error) {
	interceptor := InterceptorFactory(
		func(opt *IOInterceptorOptions[R]) *prometheus.Timer {
			return prometheus.NewTimer(watermarkIOLatency.WithLabelValues(opt.Backend, opt.Operation, opt.TableName))
		},
		func(opt *IOInterceptorOptions[R], state *prometheus.Timer, err error) {
			if state != nil {
				state.ObserveDuration()
			}
			result := "success"
			if err != nil {
				result = "error"
			}
			watermarkIOOpsTotal.WithLabelValues(opt.Backend, opt.Operation, opt.TableName, result).Inc()
		},
	)
	return interceptor(opt)
}

func RecordIOError(backend, errorType, tableName, operation string) {
	watermarkIOErrors.WithLabelValues(backend, errorType, tableName, operation).Inc()
}

func init() {
	prometheus.MustRegister(watermarkOpsTotal)
	prometheus.MustRegister(watermarkOpDuration)
	prometheus.MustRegister(watermarkIOOpsTotal)
	prometheus.MustRegister(watermarkIOLatency)
	prometheus.MustRegister(watermarkIOErrors)
}
