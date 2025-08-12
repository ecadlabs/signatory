package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	policyViolationCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "policy_violation_total",
		Help: "Total count of policy violations",
	}, []string{"violation_type", "address", "operation_type"})

	watermarkRejectionCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "watermark_rejection_total",
		Help: "Total count of operations rejected due to watermark protection",
	}, []string{"address", "operation_type", "chain_id", "reason"})

	// Authentication failure metrics
	authFailureCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "authentication_failure_total",
		Help: "Total count of authentication failures",
	}, []string{"status", "auth_method", "client_ip"})
)

func init() {
	prometheus.MustRegister(policyViolationCount)
	prometheus.MustRegister(watermarkRejectionCount)
	prometheus.MustRegister(authFailureCount)
}

func PolicyViolation(violationType, address, operationType string) {
	policyViolationCount.WithLabelValues(violationType, address, operationType).Inc()
}

func WatermarkRejection(address, operationType, chainId, reason string) {
	watermarkRejectionCount.WithLabelValues(address, operationType, chainId, reason).Inc()
}

func AuthenticationFailure(status, authMethod, clientIp string) {
	authFailureCount.WithLabelValues(status, authMethod, clientIp).Inc()
}
