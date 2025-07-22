package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	stderr "errors"
	"io"
	"net"
	"net/http"

	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/middlewares"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const defaultAddr = ":6732"

// Signer interface representing a Signer (currently implemented by Signatory)
type Signer interface {
	Sign(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, error)
	SignSequencerBlueprint(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, []byte, error)
	SignSequencerSignal(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, []byte, error)
	ProvePossession(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, error)
	GetPublicKey(ctx context.Context, keyHash crypt.PublicKeyHash) (*signatory.PublicKey, error)
}

// Server struct containing the information necessary to run a tezos remote signers
type Server struct {
	Auth    auth.AuthorizedKeysStorage
	MidWare *middlewares.JWTMiddleware
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

func (s *Server) authenticateSignRequest(req *signatory.SignRequest, r *http.Request) error {
	v := r.FormValue("authentication")
	if v == "" {
		return errors.Wrap(stderr.New("missing authentication signature field"), http.StatusUnauthorized)
	}

	authBytes, err := signatory.AuthenticatedBytesToSign(req)
	if err != nil {
		return errors.Wrap(err, http.StatusBadRequest)
	}

	sig, err := crypt.ParseSignature([]byte(v))
	if err != nil {
		return errors.Wrap(err, http.StatusBadRequest)
	}
	hashes, err := s.Auth.ListPublicKeys(r.Context())
	if err != nil {
		return err
	}

	for _, pkh := range hashes {
		pub, err := s.Auth.GetPublicKey(r.Context(), pkh)
		if err != nil {
			return err
		}

		if sig.Verify(pub, authBytes) {
			req.ClientPublicKeyHash = pkh
			return nil
		}
	}

	return errors.Wrap(stderr.New("invalid authentication signature"), http.StatusForbidden)
}

func (s *Server) processInput(r *http.Request) (*signatory.SignRequest, error) {
	pkh, err := b58.ParsePublicKeyHash([]byte(mux.Vars(r)["key"]))
	if err != nil {
		return nil, errors.Wrap(err, http.StatusBadRequest)
	}
	signRequest := signatory.SignRequest{
		PublicKeyHash: pkh,
	}
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		panic(err) // shouldn't happen with Go standard library
	}
	signRequest.Source = net.ParseIP(source)

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger().Errorf("Error reading POST content: %v", err)
		return nil, err
	}

	var req string
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errors.Wrap(err, http.StatusBadRequest)
	}

	signRequest.Message, err = hex.DecodeString(req)
	if err != nil {
		return nil, errors.Wrap(err, http.StatusBadRequest)
	}

	if s.Auth != nil {
		if err = s.authenticateSignRequest(&signRequest, r); err != nil {
			s.logger().Error(err)
			return nil, err
		}
	}

	return &signRequest, nil
}

func (s *Server) signHandler(w http.ResponseWriter, r *http.Request) {
	signRequest, err := s.processInput(r)
	if err != nil {
		tezosJSONError(w, err)
		return
	}

	signature, err := s.Signer.Sign(r.Context(), signRequest)
	if err != nil {
		s.logger().Errorf("Error signing request: %v", err)
		tezosJSONError(w, err)
		return
	}

	resp := struct {
		Signature crypt.Signature `json:"signature"`
	}{
		Signature: signature,
	}
	jsonResponse(w, http.StatusOK, &resp)
}

func (s *Server) sequencerBlueprintHandler(w http.ResponseWriter, r *http.Request) {
	signRequest, err := s.processInput(r)
	if err != nil {
		tezosJSONError(w, err)
		return
	}

	signature, data, err := s.Signer.SignSequencerBlueprint(r.Context(), signRequest)
	if err != nil {
		s.logger().Errorf("Error signing request: %v", err)
		tezosJSONError(w, err)
		return
	}

	resp := struct {
		Signature                crypt.Signature `json:"signature"`
		SignedSequencerBlueprint string          `json:"signed_sequencer_blueprint"`
	}{
		Signature:                signature,
		SignedSequencerBlueprint: hex.EncodeToString(data),
	}
	jsonResponse(w, http.StatusOK, &resp)
}

func (s *Server) sequencerSignalHandler(w http.ResponseWriter, r *http.Request) {
	signRequest, err := s.processInput(r)
	if err != nil {
		tezosJSONError(w, err)
		return
	}

	signature, data, err := s.Signer.SignSequencerSignal(r.Context(), signRequest)
	if err != nil {
		s.logger().Errorf("Error signing request: %v", err)
		tezosJSONError(w, err)
		return
	}

	resp := struct {
		Signature             crypt.Signature `json:"signature"`
		SignedSequencerSignal string          `json:"signed_sequencer_signal"`
	}{
		Signature:             signature,
		SignedSequencerSignal: hex.EncodeToString(data),
	}
	jsonResponse(w, http.StatusOK, &resp)
}

func (s *Server) getKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyHash := mux.Vars(r)["key"]
	pkh, err := b58.ParsePublicKeyHash([]byte(keyHash))
	if err != nil {
		tezosJSONError(w, errors.Wrap(err, http.StatusBadRequest))
		return
	}
	key, err := s.Signer.GetPublicKey(r.Context(), pkh)
	if err != nil {
		tezosJSONError(w, err)
		return
	}

	resp := struct {
		PublicKey crypt.PublicKey `json:"public_key"`
	}{
		PublicKey: key.PublicKey(),
	}
	jsonResponse(w, http.StatusOK, &resp)
}

func (s *Server) authorizedKeysHandler(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		AuthorizedKeys []crypt.PublicKeyHash `json:"authorized_keys,omitempty"`
	}{}

	if s.Auth != nil {
		var err error
		resp.AuthorizedKeys, err = s.Auth.ListPublicKeys(r.Context())
		if err != nil {
			tezosJSONError(w, err)
			return
		}
	}

	jsonResponse(w, http.StatusOK, &resp)
}

func (s *Server) blsProveHandler(w http.ResponseWriter, r *http.Request) {
	pkh, err := b58.ParsePublicKeyHash([]byte(mux.Vars(r)["key"]))
	if err != nil {
		tezosJSONError(w, errors.Wrap(err, http.StatusBadRequest))
		return
	}
	signRequest := signatory.SignRequest{
		PublicKeyHash: pkh,
	}
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		panic(err) // shouldn't happen with Go standard library
	}
	signRequest.Source = net.ParseIP(source)

	if s.Auth != nil {
		if err = s.authenticateSignRequest(&signRequest, r); err != nil {
			s.logger().Error(err)
			tezosJSONError(w, err)
			return
		}
	}

	signature, err := s.Signer.ProvePossession(r.Context(), &signRequest)
	if err != nil {
		s.logger().Errorf("Error signing request: %v", err)
		tezosJSONError(w, err)
		return
	}

	resp := struct {
		BlsProvePossession crypt.Signature `json:"bls_prove_possession"`
	}{
		BlsProvePossession: signature,
	}
	jsonResponse(w, http.StatusOK, &resp)
}

// Handler returns new Signatory HTTP API handler
func (s *Server) Handler() (http.Handler, error) {
	if s.Auth != nil {
		hashes, err := s.Auth.ListPublicKeys(context.Background())
		if err != nil {
			return nil, err
		}
		s.logger().Infof("Authorized keys: %v", hashes)
	}

	r := mux.NewRouter()
	r.Use((&middlewares.Logging{}).Handler)
	if s.MidWare != nil {
		r.Use(s.MidWare.AuthHandler)
	}

	r.Methods("POST").Path("/login").HandlerFunc(s.MidWare.LoginHandler)
	r.Methods("POST").Path("/keys/{key}").HandlerFunc(s.signHandler)
	r.Methods("POST").Path("/keys/{key}/sequencer_blueprint").HandlerFunc(s.sequencerBlueprintHandler)
	r.Methods("POST").Path("/keys/{key}/sequencer_signal").HandlerFunc(s.sequencerSignalHandler)
	r.Methods("GET").Path("/keys/{key}").HandlerFunc(s.getKeyHandler)
	r.Methods("GET").Path("/bls_prove_possession/{key}").HandlerFunc(s.blsProveHandler)
	r.Methods("GET").Path("/authorized_keys").HandlerFunc(s.authorizedKeysHandler)

	return r, nil
}

// New returns a new http server with Signatory HTTP API handler. See Handler
func (s *Server) New() (*http.Server, error) {
	addr := s.Address
	if addr == "" {
		addr = defaultAddr
	}
	h, err := s.Handler()
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler: h,
		Addr:    addr,
	}
	return srv, nil
}
