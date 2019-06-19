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

// Health interface for a service that had a ready func
type Health interface {
	Ready() bool
}

// UtilityServer struct containing the information necessary to run a utility endpoints
type UtilityServer struct {
	config        *config.ServerConfig
	srv           *http.Server
	healthService []Health
	shuttingDown  bool
}

// NewUtilityServer create a new utility server struct
func NewUtilityServer(config *config.ServerConfig, healthService []Health) *UtilityServer {
	return &UtilityServer{config: config, healthService: healthService, shuttingDown: false}
}

func (u *UtilityServer) live(w http.ResponseWriter, r *http.Request) {
	// Always live
	fmt.Fprintf(w, "ok")
}

func (u *UtilityServer) isReady() bool {
	if u.shuttingDown {
		return false
	}

	for _, srv := range u.healthService {
		if !srv.Ready() {
			return false
		}
	}
	return true
}

func (u *UtilityServer) ready(w http.ResponseWriter, r *http.Request) {
	if u.isReady() {
		fmt.Fprintf(w, "ready")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "not ready")
	}
}

func (u *UtilityServer) createRootHandler() http.Handler {
	r := mux.NewRouter()
	r.Use((&Logging{}).Handler)
	r.Methods("GET").Path("/metrics").Handler(metrics.Handler)
	r.HandleFunc("/healthz/live", u.live).Methods("GET")
	r.HandleFunc("/healthz/ready", u.ready).Methods("GET")
	return r
}

// Serve start the server and register route
func (u *UtilityServer) Serve() error {
	handlers := u.createRootHandler()
	binding := fmt.Sprintf(":%d", u.config.UtilityPort)

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
	u.shuttingDown = true
	afterFunc()
	if u.srv != nil {
		return u.srv.Shutdown(ctx)
	}
	return nil
}
