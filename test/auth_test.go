//go:build !integration

package test_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/hashmap"
	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAuthenticatedRequest(t *testing.T) {
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPubTz, err := tz.NewPublicKey(signPub)
	require.NoError(t, err)

	authPub1, authPriv1, _ := ed25519.GenerateKey(rand.Reader)
	authPubTz1, err := tz.NewPublicKey(authPub1)
	require.NoError(t, err)

	authPub2, authPriv2, _ := ed25519.GenerateKey(rand.Reader)
	authPubTz2, err := tz.NewPublicKey(authPub2)
	require.NoError(t, err)

	_, authPriv3, _ := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	type testCase struct {
		name       string
		signWith   crypto.Signer
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

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{{PrivateKey: signPriv}}, "Mock")
		}),
		Policy: hashmap.New[tz.EncodedPublicKeyHash]([]hashmap.KV[tz.PublicKeyHash, *signatory.PublicKeyPolicy]{
			{
				Key: signPubTz.Hash(),
				Val: &signatory.PublicKeyPolicy{
					AllowedRequests:     []string{"generic", "block", "endorsement"},
					AllowedOps:          []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					AuthorizedKeyHashes: []tz.PublicKeyHash{authPubTz1.Hash()},
				},
			},
		}),
	}

	signer, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)
	require.NoError(t, signer.Unlock(context.Background()))

	srv := server.Server{
		Signer: signer,
		Auth:   auth.Must(auth.StaticAuthorizedKeysFromRaw(authPubTz1, authPubTz2)),
	}

	handler, err := srv.Handler()
	require.NoError(t, err)

	s := httptest.NewServer(handler)
	defer s.Close()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse(s.URL + "/keys/" + signPubTz.Hash().String())
			if c.signWith != nil {
				msgBytes, err := hex.DecodeString(message)
				require.NoError(t, err)
				authBytes, err := signatory.AuthenticatedBytesToSign(&signatory.SignRequest{
					PublicKeyHash: signPubTz.Hash(),
					Message:       msgBytes,
				})
				require.NoError(t, err)
				sig, err := cryptoutils.Sign(c.signWith, authBytes)
				require.NoError(t, err)
				tzSig, err := tz.NewSignature(sig)
				require.NoError(t, err)

				u.RawQuery = url.Values{
					"authentication": []string{tzSig.String()},
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
