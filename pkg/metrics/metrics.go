package metrics

import (
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler is an alias for default Prometheus HTTP handler
var Handler = promhttp.Handler()

type InterceptorOptions[R any] interface {
	GetTargetFunc() func() (R, error)
}

func InterceptorFactory[O InterceptorOptions[R], R, S any](preExec func(O) S, postExec func(O, S, error)) func(O) (R, error) {
	return func(opt O) (R, error) {
		var state S
		if preExec != nil {
			state = preExec(opt)
		}
		result, err := opt.GetTargetFunc()()
		if postExec != nil {
			postExec(opt, state, err)
		}
		return result, err
	}
}
