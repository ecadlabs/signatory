package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/metrics"
	"github.com/gorilla/mux"
)

// HealthService interface for a service that had a ready func
type HealthService interface {
	Ready() bool
}

// UtilityServer struct containing the information necessary to run a utility endpoints
type UtilityServer struct {
	config *config.ServerConfig
	srv    *http.Server
}

// NewUtilityServer create a new utility server struct
func NewUtilityServer(config *config.ServerConfig) *UtilityServer {
	return &UtilityServer{config: config}
}

func (u *UtilityServer) live(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ok")
}

func (u *UtilityServer) ready(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ok")
}

func (u *UtilityServer) createRootHandler() http.Handler {
	r := mux.NewRouter()
	r.Methods("GET").Path("/metrics").Handler(metrics.Handler)
	r.HandleFunc("/healthz/live", u.live).Methods("GET")
	r.HandleFunc("/healthz/ready", u.ready).Methods("GET")
	return r
}

// Serve start the server and register route
func (u *UtilityServer) Serve() error {
	handlers := u.createRootHandler()
	binding := fmt.Sprintf(":%d", u.config.Port+1)

	srv := &http.Server{
		Handler:      handlers,
		Addr:         binding,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	u.srv = srv

	return srv.ListenAndServe()
}

// ShutdownAfter shutdown the server after executing afterFunc
func (u *UtilityServer) ShutdownAfter(ctx context.Context, afterFunc func()) error {
	afterFunc()
	if u.srv != nil {
		return u.srv.Shutdown(ctx)
	}
	return nil
}
