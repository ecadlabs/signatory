package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"encoding/json"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/ecadlabs/signatory/pkg/config"
)

const (
	msgErrReadingRequest  = "error reading the request"
	msgErrSigningRequest  = "error signing the request"
	msgErrFetchingRequest = "error fetching key the request"
)

// Signer interface representing a Signer
type Signer interface {
	Sign(ctx context.Context, keyHash string, message []byte) (string, error)
	GetPublicKey(ctx context.Context, keyHash string) (string, error)
}

// Server struct containing the information necessary to run a tezos remote signers
type Server struct {
	signatory Signer
	config    *config.ServerConfig
	srv       *http.Server
	logger    log.FieldLogger
}

type errorResponse struct {
	Error string `json:"error"`
}

type signResponse struct {
	Signature string `json:"signature"`
}

type pubKeyResponse struct {
	PublicKey string `json:"public_key"`
}

// NewServer create a new server struct
func NewServer(signatory Signer, config *config.ServerConfig, logger log.FieldLogger) *Server {
	s := &Server{signatory: signatory, config: config, logger: logger}
	if s.logger == nil {
		s.logger = log.StandardLogger()
	}
	return s
}

func (server *Server) handleError(w http.ResponseWriter, msg string) {
	response := errorResponse{Error: msg}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		server.logger.Error("Error encoding error response")
	}
}

func (server *Server) validateOperation(op []byte) ([]byte, error) {
	// Must begin and end with quotes
	opString := strings.TrimSpace(string(op))
	if !strings.HasPrefix(opString, "\"") || !strings.HasSuffix(opString, "\"") {
		return nil, fmt.Errorf("Invalid operation")
	}
	opString = strings.Trim(opString, "\"")

	// Must be valid hex chars
	parsedHex, err := hex.DecodeString(opString)
	if err != nil {
		return nil, fmt.Errorf("Invalid operation")
	}
	return parsedHex, nil
}

// Sign is the HTTP request handler that signs operations
func (server *Server) Sign(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	requestedKeyHash := params["key"]

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		server.logger.Error("Error reading POST content: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		server.handleError(w, msgErrReadingRequest)
		return
	}

	parsedHex, err := server.validateOperation(body)

	if err != nil {
		server.logger.Error("Error reading POST content: ", err)

		w.WriteHeader(http.StatusBadRequest)
		server.handleError(w, msgErrReadingRequest)
		return
	}

	signed, err := server.signatory.Sign(r.Context(), requestedKeyHash, parsedHex)

	if err != nil {
		server.logger.Error("Error signing request:", err)

		w.WriteHeader(http.StatusInternalServerError)
		server.handleError(w, msgErrSigningRequest)
	} else {
		response := signResponse{Signature: signed}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			server.logger.Error("Error encoding signing response")
		}
	}
}

// GetKey s the HTTP request handler that get the public key from a public key hash
func (server *Server) GetKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	requestedKeyHash := params["key"]

	pubKey, err := server.signatory.GetPublicKey(r.Context(), requestedKeyHash)
	if err != nil {
		server.logger.Println("Error fetching key:", err)

		w.WriteHeader(http.StatusInternalServerError)
		server.handleError(w, msgErrFetchingRequest)
	} else {
		response := pubKeyResponse{PublicKey: pubKey}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			server.logger.Error("Error encoding public key response")
		}
	}
}

func (server *Server) authorizedKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{}")
}

func (server *Server) createRootHandler() http.Handler {
	r := mux.NewRouter()
	r.Use((&Logging{}).Handler)
	r.HandleFunc("/keys/{key}", server.Sign).Methods("POST")
	r.HandleFunc("/keys/{key}", server.GetKey).Methods("GET")
	r.HandleFunc("/authorized_keys", server.authorizedKeys).Methods("GET")
	return r
}

// Serve start the server and register route
func (server *Server) Serve() error {
	handlers := server.createRootHandler()

	binding := fmt.Sprintf(":%d", server.config.Port)

	srv := &http.Server{
		Handler:      handlers,
		Addr:         binding,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	server.srv = srv

	return srv.ListenAndServe()
}

// Shutdown the server
func (server *Server) Shutdown(ctx context.Context) error {
	if server.srv != nil {
		return server.srv.Shutdown(ctx)
	}
	return nil
}