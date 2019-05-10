package server

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
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

func (server *Server) sign(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	requestedKeyHash := params["key"]

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
	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	requestedKeyHash := params["key"]

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

func (server *Server) createRootHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/keys/{key}", server.sign).Methods("POST")
	r.HandleFunc("/keys/{key}", server.getKey).Methods("GET")
	r.HandleFunc("/keys/{key}", server.authorizedKeys).Methods("GET")
	return r
}

// Serve start the server and register route
func (server *Server) Serve() {
	handlers := server.createRootHandler()

	binding := fmt.Sprintf(":%d", server.config.Port)

	srv := &http.Server{
		Handler:      handlers,
		Addr:         binding,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Infof("Server listening on port: %d", server.config.Port)

	log.Error(srv.ListenAndServe())
}
