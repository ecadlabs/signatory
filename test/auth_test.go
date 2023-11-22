package test_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/tezos/server"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/manager"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func generateKey() (crypt.PublicKey, crypt.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return crypt.Ed25519PublicKey(pub), crypt.Ed25519PrivateKey(priv), nil
}

func TestAuthenticatedRequest(t *testing.T) {
	signPub, signPriv, err := generateKey()
	require.NoError(t, err)
	authPub1, authPriv1, err := generateKey()
	require.NoError(t, err)
	authPub2, authPriv2, err := generateKey()
	require.NoError(t, err)
	_, authPriv3, err := generateKey()
	require.NoError(t, err)

	type testCase struct {
		name       string
		signWith   crypt.PrivateKey
		statusCode int
	}

	cases := []testCase{
		{
			name:       "Ok",
			signWith:   authPriv1,
			statusCode: http.StatusOK,
		},
		{
			name:       "No signature",
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "Disabled in policy",
			signWith:   authPriv2,
			statusCode: http.StatusForbidden,
		},
		{
			name:       "Invalid signature",
			signWith:   authPriv3,
			statusCode: http.StatusForbidden,
		},
	}

	message := "03a11f5f176e553a11cf184bb2b15f09f55dfc5dcb2d26d79bf5dd099d074d5f5d6c0079cae4c9a1885f17d3995619bf28636c4394458b820af19172c35000904e0000712c4c4270d9e7f512115310d8ec6acfcd878bef00"

	conf := tezos.Config{
		ManagerConfig: manager.ManagerConfig{
			Vaults: map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
			VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
				return memory.New([]*memory.PrivateKey{{PrivateKey: signPriv}}, "Mock")
			}),
		},
		Watermark: tezos.IgnoreWatermark{},
		Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*tezos.PublicKeyPolicy]{
			{
				Key: signPub.Hash(),
				Val: &tezos.PublicKeyPolicy{
					AllowedRequests:     []string{"generic", "block", "endorsement"},
					AllowedOps:          []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					AuthorizedKeyHashes: []crypt.PublicKeyHash{authPub1.Hash()},
				},
			},
		}),
	}

	signer, err := tezos.New(context.Background(), &conf)
	require.NoError(t, err)
	require.NoError(t, signer.Unlock(context.Background()))

	srv := server.Server{
		Signer: signer,
		Auth:   auth.Must(auth.StaticAuthorizedKeys(authPub1, authPub2)),
	}

	handler, err := srv.Handler()
	require.NoError(t, err)

	s := httptest.NewServer(handler)
	defer s.Close()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse(s.URL + "/keys/" + signPub.Hash().String())
			if c.signWith != nil {
				msgBytes, err := hex.DecodeString(message)
				require.NoError(t, err)
				authBytes, err := tezos.AuthenticatedBytesToSign(&tezos.SignRequest{
					PublicKeyHash: signPub.Hash(),
					Message:       msgBytes,
				})
				require.NoError(t, err)
				sig, err := c.signWith.Sign(authBytes)
				require.NoError(t, err)

				u.RawQuery = url.Values{
					"authentication": []string{sig.String()},
				}.Encode()
			}

			body := strings.NewReader("\"" + message + "\"")
			req, err := http.NewRequest("POST", u.String(), body)
			require.NoError(t, err)

			resp, err := s.Client().Do(req)
			require.NoError(t, err)

			require.Equal(t, c.statusCode, resp.StatusCode)
		})
	}
}
