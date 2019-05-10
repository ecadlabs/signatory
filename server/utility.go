package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/metrics"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// UtilityServer struct containing the information necessary to run a utility endpoints
type UtilityServer struct {
	config *config.ServerConfig
}

// NewUtilityServer create a new utility server struct
func NewUtilityServer(config *config.ServerConfig) *UtilityServer {
	return &UtilityServer{config: config}
}

func (u *UtilityServer) createRootHandler() http.Handler {
	r := mux.NewRouter()
	metricsHandler := metrics.RegisterHandler()
	r.HandleFunc("/metrics", metricsHandler.ServeHTTP).Methods("GET")
	return r
}

// Serve start the server and register route
func (u *UtilityServer) Serve() {
	handlers := u.createRootHandler()
	binding := fmt.Sprintf(":%d", u.config.Port+1)

	srv := &http.Server{
		Handler:      handlers,
		Addr:         binding,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Infof("Utility Server listening on port: %d", u.config.Port+1)

	log.Error(srv.ListenAndServe())
}
