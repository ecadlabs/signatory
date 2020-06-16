package server

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ecadlabs/signatory/pkg/metrics"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const timeout = time.Second * 10
const defaultUtilityAddr = ":9583"

// UtilityServer struct containing the information necessary to run a utility endpoints
type UtilityServer struct {
	Address string
	Health  vault.ReadinessChecker
	Logger  log.FieldLogger

	shuttingDown int32
}

func (u *UtilityServer) logger() log.FieldLogger {
	if u.Logger != nil {
		return u.Logger
	}
	return log.StandardLogger()
}

func (u *UtilityServer) readyHandler(w http.ResponseWriter, r *http.Request) {
	var ok bool
	if atomic.LoadInt32(&u.shuttingDown) == 0 {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		var err error
		ok, err = u.Health.Ready(ctx)
		if err != nil {
			jsonError(w, err)
			return
		}
	}

	resp := struct {
		Ready bool `json:"ready"`
	}{
		Ready: ok,
	}

	var status int
	if ok {
		status = http.StatusOK
	} else {
		status = http.StatusServiceUnavailable
	}

	jsonResponse(w, status, &resp)
}

type utilityServer struct {
	*http.Server
	srv *UtilityServer
}

// New returns a new http server with registered routes
func (u *UtilityServer) New() HTTPServer {
	r := mux.NewRouter()
	r.Methods("GET").Path("/metrics").Handler(metrics.Handler)
	r.Methods("GET").Path("/healthz").HandlerFunc(u.readyHandler)

	addr := u.Address
	if addr == "" {
		addr = defaultUtilityAddr
	}

	srv := &http.Server{
		Handler: r,
		Addr:    addr,
	}

	u.logger().Printf("Utility HTTP server is listening for connections on %s", addr)
	return &utilityServer{
		Server: srv,
		srv:    u,
	}
}

// Shutdown shutdown the server after executing afterFunc
func (u *utilityServer) Shutdown(ctx context.Context) error {
	atomic.StoreInt32(&u.srv.shuttingDown, 1)
	return u.Server.Shutdown(ctx)
}
