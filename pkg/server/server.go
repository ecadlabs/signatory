package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	stderr "errors"
	"io/ioutil"
	"net/http"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/server/auth"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const defaultAddr = ":6732"

// Signer interface representing a Signer (currently implemented by Signatory)
type Signer interface {
	Sign(ctx context.Context, req *signatory.SignRequest) (string, error)
	GetPublicKey(ctx context.Context, keyHash string) (*signatory.PublicKey, error)
}

// Server struct containing the information necessary to run a tezos remote signers
type Server struct {
	Auth    auth.AuthorizedKeysStorage
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

func signRequestToSign(req *signatory.SignRequest) ([]byte, error) {
	keyHashBytes, err := tezos.EncodeBinaryPublicKeyHash(req.PublicKeyHash)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 2+len(req.Message)+len(keyHashBytes))
	data[0] = 4
	data[1] = 1
	copy(data[2:], keyHashBytes)
	copy(data[2+len(keyHashBytes):], req.Message)
	return data, nil
}

func (s *Server) authenticateSignRequest(req *signatory.SignRequest, r *http.Request) error {
	v := r.FormValue("authentication")
	if v == "" {
		return errors.Wrap(stderr.New("missing authentication signature field"), http.StatusUnauthorized)
	}

	signed, err := signRequestToSign(req)
	if err != nil {
		return errors.Wrap(err, http.StatusBadRequest)
	}
	digest := tezos.DigestFunc(signed)

	sig, err := tezos.ParseSignature(v, nil)
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

		err = cryptoutils.Verify(pub, digest[:], sig)
		if err == nil {
			req.ClientPublicKeyHash = pkh
			return nil
		} else if err != cryptoutils.ErrSignature {
			return err
		}
	}

	return errors.Wrap(stderr.New("invalid authentication signature"), http.StatusForbidden)
}

func (s *Server) signHandler(w http.ResponseWriter, r *http.Request) {
	signRequest := signatory.SignRequest{
		PublicKeyHash: mux.Vars(r)["key"],
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger().Errorf("Error reading POST content: %v", err)
		tezosJSONError(w, err)
		return
	}

	var req string
	if err := json.Unmarshal(body, &req); err != nil {
		tezosJSONError(w, errors.Wrap(err, http.StatusBadRequest))
		return
	}

	signRequest.Message, err = hex.DecodeString(req)
	if err != nil {
		tezosJSONError(w, errors.Wrap(err, http.StatusBadRequest))
		return
	}

	if s.Auth != nil {
		if err = s.authenticateSignRequest(&signRequest, r); err != nil {
			s.logger().Error(err)
			tezosJSONError(w, err)
			return
		}
	}

	signature, err := s.Signer.Sign(r.Context(), &signRequest)
	if err != nil {
		s.logger().Errorf("Error signing request: %v", err)
		tezosJSONError(w, err)
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
		tezosJSONError(w, err)
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
	resp := struct {
		AuthorizedKeys []string `json:"authorized_keys,omitempty"`
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
	r.Use((&Logging{}).Handler)

	r.Methods("POST").Path("/keys/{key}").HandlerFunc(s.signHandler)
	r.Methods("GET").Path("/keys/{key}").HandlerFunc(s.getKeyHandler)
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
