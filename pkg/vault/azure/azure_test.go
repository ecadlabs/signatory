package azure_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/jwk"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	ahsm "github.com/ecadlabs/signatory/pkg/vault/azure"
	"github.com/ecadlabs/signatory/pkg/vault/azure/auth"
	jk "github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type testCase struct {
	name       string
	raw        string
	privkey    *ecdsa.PrivateKey
	pubkey     *ecdsa.PublicKey
	pkh        string
	statusCode int
}

type testClient struct {
	ahsm.HttpClient
}

var cases = make([]testCase, 1)

func jsonResponse(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func tezosJSONError(w http.ResponseWriter, err error) {
	type errorResponse []struct {
		ID   string `json:"id,omitempty"`
		Kind string `json:"kind,omitempty"`
		Msg  string `json:"msg,omitempty"`
	}

	var status int
	if e, ok := err.(errors.HTTPError); ok {
		status = e.HTTPStatus()
	} else {
		status = http.StatusInternalServerError
	}

	res := errorResponse{
		{
			ID:   "failure",
			Kind: "temporary",
			Msg:  err.Error(),
		},
	}
	jsonResponse(w, status, &res)
}

func jsonError(w http.ResponseWriter, err error) {
	type errorResponse struct {
		Error string `json:"error,omitempty"`
	}

	var status int
	if e, ok := err.(errors.HTTPError); ok {
		status = e.HTTPStatus()
	} else {
		status = http.StatusInternalServerError
	}

	res := errorResponse{
		Error: err.Error(),
	}

	jsonResponse(w, status, &res)
}

func getKey(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Abi-->:getKey:  ", w)
	type keyAttributes struct {
		Created       int    `json:"created"`
		Enabled       bool   `json:"enabled"`
		Exp           int    `json:"exp"`
		Nbf           int    `json:"nbf"`
		RecoveryLevel string `json:"recoveryLevel"`
		Updated       int    `json:"updated"`
	}
	type keyBundle struct {
		Attributes keyAttributes          `json:"attributes"`
		Key        jwk.JWK                `json:"key"`
		Managed    bool                   `json:"managed"`
		Tags       map[string]interface{} `json:"tags"`
	}
	resp := keyBundle{
		Attributes: keyAttributes{},
		// Key:        cases[0].pubkey,
		Managed: true,
	}

	jsonResponse(w, http.StatusOK, &resp)
}

func sign(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Abi-->:sign:  ", w)
}

func importPkey(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Abi-->:importPkey:  ", w)
}

func mgmtRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Abi-->:mgmtRequest:  ", w)
	// jsonResponse(w http.ResponseWriter, status int, v interface{})
}

func (h *testClient) Do(req *http.Request) (*http.Response, error) {
	fmt.Println("Abi-->:func (h *testClient) Do:- ", req)
	return nil, nil
}

func getVault(ctx context.Context) (*ahsm.Vault, error) {

	ac := auth.Config{
		Tenant:   "50c46f11-1d0a-4c56-b468-1bcb03a8f69e",
		ClientID: "b6328cc5-98f9-44bd-a688-7cdff9b9bcb4",
		// ClientSecret:                "sign-abi",
		// ClientPKCS12Certificate:     "sign-cert",
		// ClientCertificate:           "client_certificate",
		ClientCertificateThumbprint: "643F14403B695090D8A7C0325117EF242513E052",
		PrivateKey:                  "/bin/service-principal.key",
		PrivateKeyPassword:          "decrypt_password",
	}

	return ahsm.New(ctx, &ahsm.Config{
		Config:         ac,
		Vault:          "azure",
		SubscriptionID: "be273d20-6dc1-4bbc-ab26-15d082cca908",
		ResourceGroup:  "signatory",
	})
}

func TestAzureVault(t *testing.T) {
	t.Log("TestAzureVault-0")

	v, err := getVault(nil) //ctx)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jkey, err := jk.New(privateKey)
	t.Log("Abi-->: ", jkey, " - ", jkey.KeyType().String())

	publicKey := &privateKey.PublicKey
	pub, err := tezos.EncodePublicKeyHash(publicKey)
	require.NoError(t, err)

	t.Log("TestAzureVault-2")
	cases[0] = testCase{
		name:       "azure hsm sign",
		raw:        "\"03a11f5f176e553a11cf184bb2b15f09f55dfc5dcb2d26d79bf5dd099d074d5f5d6c0079cae4c9a1885f17d3995619bf28636c4394458b820af19172c35000904e0000712c4c4270d9e7f512115310d8ec6acfcd878bef00\"",
		privkey:    privateKey,
		pubkey:     publicKey,
		pkh:        pub,
		statusCode: http.StatusOK,
	}
	t.Log("TestAzureVault-3")
	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"azure": {Driver: "azure"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return v, nil
		}),
		Policy: map[string]*signatory.Policy{
			cases[0].pkh: {
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
			},
		},
	}

	signer, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)
	require.NoError(t, signer.Unlock(context.Background()))
	t.Log("TestAzureVault-4")
	srv := server.Server{
		Signer: signer,
	}
	t.Log("TestAzureVault-5")
	handler, err := srv.Handler()
	require.NoError(t, err)
	t.Log("TestAzureVault-6")
	s := httptest.NewServer(handler)
	defer s.Close()
	t.Log("TestAzureVault-7")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Log("TestAzureVault-8")
			body := strings.NewReader(c.raw)
			u, _ := url.Parse(s.URL + "/keys/" + c.pkh)
			t.Log("TestAzureVault-9")
			req, err := http.NewRequest("GET", u.String(), body)
			require.NoError(t, err)
			t.Log("TestAzureVault-10")
			resp, err := s.Client().Do(req)
			require.NoError(t, err)

			require.Equal(t, c.statusCode, resp.StatusCode)
		})
	}

}
