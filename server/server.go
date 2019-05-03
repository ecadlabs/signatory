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

	"github.com/ecadlabs/signatory/signatory"
)

// Server struct containing the information necessary to run a tezos remote signers
type Server struct {
	signatory *signatory.Signatory
}

// NewServer create a new server struct
func NewServer(signatory *signatory.Signatory) *Server {
	return &Server{signatory: signatory}
}

// RouteKeys validates a /key/ request and routes based on HTTP Method
func (server *Server) RouteKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case "GET":
		server.RouteKeysGET(w, r)
	case "POST":
		server.RouteKeysPOST(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "{\"error\":\"bad_verb\"}")
	}
}

// RouteKeysPOST attempts to sign the provided message from the provided keys
func (server *Server) RouteKeysPOST(w http.ResponseWriter, r *http.Request) {
	// Route: /keys/<key>
	// Method: POST
	// Response Body: `{"signature": "p2sig....."}`
	// Status: 200
	// mimetype: "application/json"

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

// RouteKeysGET returns the corresponding public key to this public key *hash*
func (server *Server) RouteKeysGET(w http.ResponseWriter, r *http.Request) {
	// Route: /keys/<key>
	// Response Body: `{"public_key": "<key>"}`
	// Status: 200
	// mimetype: "application/json"
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

// RouteAuthorizedKeys list all of they keys that we currently support.  We choose to
// return an empty set to obscure our secrets.
func (server *Server) RouteAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	// Route: /authorized_keys
	// Response Body: `{}`
	// Status: 200
	// mimetype: "application/json"
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{}")
}

// shutdown gracefully
func shutdown(c chan os.Signal) {
	<-c
	log.Info("Shutting down")
	os.Exit(0)
}

// Serve start the server and register route
func (server *Server) Serve() {
	// Handle Sigterm
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go shutdown(c)

	// Routes
	http.HandleFunc("/authorized_keys", server.RouteAuthorizedKeys)
	http.HandleFunc("/keys/", server.RouteKeys)
	log.Info("Server listening on port: 80")
	log.Error(http.ListenAndServe(":80", nil))
}
