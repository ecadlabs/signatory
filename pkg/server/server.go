package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// Signer interface representing a Signer (currently implemented by Signatory)
type Signer interface {
	Sign(ctx context.Context, keyHash string, message []byte) (string, error)
	GetPublicKey(ctx context.Context, keyHash string) (*signatory.PublicKey, error)
}

// Server struct containing the information necessary to run a tezos remote signers
type Server struct {
	Signer  Signer
	Address string
	Logger  log.FieldLogger
}

func (s *Server) logger() log.FieldLogger {
	if s.Logger != nil {
		return s.Logger
	}
	return log.StandardLogger()
}

func (s *Server) signHandler(w http.ResponseWriter, r *http.Request) {
	keyHash := mux.Vars(r)["key"]

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger().Errorf("Error reading POST content: %v", err)
		jsonError(w, err)
		return
	}

	var req string
	if err := json.Unmarshal(body, &req); err != nil {
		jsonError(w, errors.Wrap(err, http.StatusBadRequest))
		return
	}

	data, err := hex.DecodeString(req)
	if err != nil {
		jsonError(w, errors.Wrap(err, http.StatusBadRequest))
		return
	}

	signature, err := s.Signer.Sign(r.Context(), keyHash, data)
	if err != nil {
		s.logger().Errorf("Error signing request: %v", err)
		jsonError(w, err)
		return
	}

	resp := struct {
		Signature string `json:"signature"`
	}{
		Signature: signature,
	}
	jsonResponse(w, http.StatusOK, &resp)
}

func (s *Server) getKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyHash := mux.Vars(r)["key"]

	key, err := s.Signer.GetPublicKey(r.Context(), keyHash)
	if err != nil {
		jsonError(w, err)
		return
	}

	resp := struct {
		PublicKey string `json:"public_key"`
	}{
		PublicKey: key.PublicKey,
	}
	jsonResponse(w, http.StatusOK, &resp)
}

func (s *Server) authorizedKeysHandler(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, &struct{}{})
}

// New returns a new http server with registered routes
func (s *Server) New() HTTPServer {
	r := mux.NewRouter()
	r.Use((&Logging{}).Handler)

	r.Methods("POST").Path("/keys/{key}").HandlerFunc(s.signHandler)
	r.Methods("GET").Path("/keys/{key}").HandlerFunc(s.getKeyHandler)
	r.Methods("GET").Path("/authorized_keys").HandlerFunc(s.authorizedKeysHandler)

	srv := &http.Server{
		Handler: r,
		Addr:    s.Address,
	}

	s.logger().Printf("HTTP server is listening for connections on %s", s.Address)
	return srv
}
