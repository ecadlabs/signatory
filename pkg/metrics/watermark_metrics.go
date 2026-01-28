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

type FileOperationInterceptorOptions[R any] struct {
	Operation  string
	TargetFunc func() (R, error)
}

func (o FileOperationInterceptorOptions[R]) GetTargetFunc() func() (R, error) {
	return o.TargetFunc
}

type DynamoDBInterceptorOptions struct {
	Operation  string
	TableName  string
	TargetFunc func() (bool, error)
}

func (o DynamoDBInterceptorOptions) GetTargetFunc() func() (bool, error) {
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

	// File backend specific metrics
	watermarkFileOpsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "watermark_file_operations_total",
		Help: "Total number of file watermark backend I/O operations",
	}, []string{"operation", "result"})

	watermarkFileLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "watermark_file_latency_seconds",
		Help:    "File watermark backend I/O latency in seconds",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 12), // 0.1ms to ~0.4s
	}, []string{"operation"})

	// AWS DynamoDB specific metrics
	watermarkDynamoDBOpsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "watermark_aws_dynamodb_operations_total",
		Help: "Total number of AWS DynamoDB watermark operations",
	}, []string{"operation", "table_name", "result"})

	watermarkDynamoDBLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "watermark_aws_dynamodb_latency_seconds",
		Help:    "AWS DynamoDB watermark operation latency in seconds",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms to ~4s
	}, []string{"operation", "table_name"})

	watermarkDynamoDBErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "watermark_aws_dynamodb_errors_total",
		Help: "Total number of AWS DynamoDB watermark errors",
	}, []string{"error_type", "table_name", "operation"})

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

func DynamoDBInterceptor(opt *DynamoDBInterceptorOptions) (bool, error) {
	interceptor := InterceptorFactory(
		func(opt *DynamoDBInterceptorOptions) *prometheus.Timer {
			return prometheus.NewTimer(watermarkDynamoDBLatency.WithLabelValues(opt.Operation, opt.TableName))
		},
		func(opt *DynamoDBInterceptorOptions, state *prometheus.Timer, err error) {
			if state != nil {
				state.ObserveDuration()
			}
			result := "success"
			if err != nil {
				result = "error"
			}
			watermarkDynamoDBOpsTotal.WithLabelValues(opt.Operation, opt.TableName, result).Inc()
		},
	)
	return interceptor(opt)
}

func FileOperationInterceptor[R any](opt *FileOperationInterceptorOptions[R]) (R, error) {
	interceptor := InterceptorFactory(
		func(opt *FileOperationInterceptorOptions[R]) *prometheus.Timer {
			return prometheus.NewTimer(watermarkFileLatency.WithLabelValues(opt.Operation))
		},
		func(opt *FileOperationInterceptorOptions[R], state *prometheus.Timer, err error) {
			if state != nil {
				state.ObserveDuration()
			}
			result := "success"
			if err != nil {
				result = "error"
			}
			watermarkFileOpsTotal.WithLabelValues(opt.Operation, result).Inc()
		},
	)
	return interceptor(opt)
}

func RecordDynamoDBError(errorType, tableName, operation string) {
	watermarkDynamoDBErrors.WithLabelValues(errorType, tableName, operation).Inc()
}

// RegisterHandler register metrics handler
func init() {
	prometheus.MustRegister(watermarkOpsTotal)
	prometheus.MustRegister(watermarkOpDuration)
	prometheus.MustRegister(watermarkFileOpsTotal)
	prometheus.MustRegister(watermarkFileLatency)
	prometheus.MustRegister(watermarkDynamoDBOpsTotal)
	prometheus.MustRegister(watermarkDynamoDBLatency)
	prometheus.MustRegister(watermarkDynamoDBErrors)
}
