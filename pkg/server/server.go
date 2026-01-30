package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	stderr "errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/metrics"
	"github.com/ecadlabs/signatory/pkg/middlewares"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const defaultAddr = ":6732"

// Signer interface representing a Signer (currently implemented by Signatory)
type Signer interface {
	Sign(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, error)
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

func (s *Server) signHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	address := "unknown"
	status := "500"
	requestType := "sign"

	defer func() {
		metrics.RecordSignHandlerRequest(startTime, address, status, requestType)
	}()

	pkh, err := b58.ParsePublicKeyHash([]byte(mux.Vars(r)["key"]))
	if err != nil {
		status = strconv.Itoa(http.StatusBadRequest)
		tezosJSONError(w, errors.Wrap(err, http.StatusBadRequest))
		return
	}
	address = string(pkh.ToBase58())

	versionStr := r.URL.Query().Get("version")
	version := utils.ParseVersionString(versionStr)
	s.logger().Infof("Signing version: %d", version)

	signRequest := signatory.SignRequest{
		PublicKeyHash: pkh,
		SignOptions: vault.SignOptions{
			Version: version,
		},
	}
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		panic(err) // shouldn't happen with Go standard library
	}
	signRequest.Source = net.ParseIP(source)

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		status = "500"
		s.logger().Errorf("Error reading POST content: %v", err)
		tezosJSONError(w, err)
		return
	}

	var req string
	if err := json.Unmarshal(body, &req); err != nil {
		status = strconv.Itoa(http.StatusBadRequest)
		tezosJSONError(w, errors.Wrap(err, http.StatusBadRequest))
		return
	}

	signRequest.Message, err = hex.DecodeString(req)
	if err != nil {
		status = strconv.Itoa(http.StatusBadRequest)
		tezosJSONError(w, errors.Wrap(err, http.StatusBadRequest))
		return
	}

	if s.Auth != nil {
		if err = s.authenticateSignRequest(&signRequest, r); err != nil {
			if val, ok := err.(errors.HTTPError); ok {
				status = strconv.Itoa(val.HTTPStatus())
			} else {
				status = "500"
			}
			metrics.AuthenticationFailure(status, "authentication", signRequest.Source.String())
			s.logger().Error(err)
			tezosJSONError(w, err)
			return
		}
	}

	signature, err := s.Signer.Sign(r.Context(), &signRequest)
	if err != nil {
		if val, ok := err.(errors.HTTPError); ok {
			status = strconv.Itoa(val.HTTPStatus())
		} else {
			status = "500"
		}
		s.logger().Errorf("Error signing request: %v", err)
		tezosJSONError(w, err)
		return
	}

	status = "200"
	resp := struct {
		Signature crypt.Signature `json:"signature"`
	}{
		Signature: signature,
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
			source, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				panic(err) // shouldn't happen with Go standard library
			}
			metrics.AuthenticationFailure(
				"n/a",
				"authorized_keys",
				source,
			)
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
			var status string
			if val, ok := err.(errors.HTTPError); ok {
				status = strconv.Itoa(val.HTTPStatus())
			} else {
				status = "n/a"
			}
			metrics.AuthenticationFailure(status, "authentication", signRequest.Source.String())
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
