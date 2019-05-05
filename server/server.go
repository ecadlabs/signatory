package server

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/signatory"
)

// Server struct containing the information necessary to run a tezos remote signers
type Server struct {
	signatory *signatory.Signatory
	config    *config.ServerConfig
}

// NewServer create a new server struct
func NewServer(signatory *signatory.Signatory, config *config.ServerConfig) *Server {
	return &Server{signatory: signatory, config: config}
}

func (server *Server) routeKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case "GET":
		server.getKey(w, r)
	case "POST":
		server.sign(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "{\"error\":\"not_allowed\"}")
	}
}

func (server *Server) sign(w http.ResponseWriter, r *http.Request) {
	requestedKeyHash := strings.Split(r.URL.Path, "/")[2]

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)

	// Must begin and end with quotes
	opString := strings.TrimSpace(string(body))
	if !strings.HasPrefix(opString, "\"") || !strings.HasSuffix(opString, "\"") {
		return
	}
	opString = strings.Trim(opString, "\"")

	// Must be valid hex chars
	parsedHex, err := hex.DecodeString(opString)
	if err != nil {
		return
	}

	if err != nil {
		log.Error("Error reading POST content: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"error\":\"%s\"}", "error reading the request")
		return
	}
	signed, err := server.signatory.Sign(requestedKeyHash, parsedHex)

	if err != nil {
		log.Error("Error signing request:", err)

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"error\":\"%s\"}", "error signing the request")
	} else {
		response := fmt.Sprintf("{\"signature\":\"%s\"}", signed)
		log.Info("Returning signed message: ", response)
		fmt.Fprintf(w, response)
	}
}

func (server *Server) getKey(w http.ResponseWriter, r *http.Request) {
	requestedKeyHash := strings.Split(r.URL.Path, "/")[2]
	pubKey, err := server.signatory.GetPublicKey(requestedKeyHash)
	if err != nil {
		log.Println("Error fetching key:", err)

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"error\":\"%s\"}", "error fetching key the request")
	} else {
		fmt.Fprintf(w, "{\"public_key\":\"%s\"}", pubKey)
	}
}

func (server *Server) authorizedKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{}")
}

func shutdown(c chan os.Signal) {
	<-c
	log.Info("Shutting down")
	os.Exit(0)
}

func (server *Server) registerRoutes() {
	http.HandleFunc("/keys/", server.routeKeys)
	http.HandleFunc("/authorized_keys", server.authorizedKeys)
}

func (server *Server) regsiterSigterm() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go shutdown(c)
}

// Serve start the server and register route
func (server *Server) Serve() {
	server.regsiterSigterm()
	server.registerRoutes()

	log.Infof("Server listening on port: %d", server.config.Port)

	binding := fmt.Sprintf(":%d", server.config.Port)

	log.Error(http.ListenAndServe(binding, nil))
}
