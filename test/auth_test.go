// +build !integration

package test_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/server/auth"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

/*
Auth:
Private Key:     edsk3xMUYWwM2Gstbeeyd1pvsoYoGGdhjej1jGZk2EdMpYsgZcj5Pm
Public Key:      edpkvN5hM4s88nzgxZGkNrVqtQfaiVpix356TFrAwQoVGrKseahWG6
Public Key Hash: tz1KpduK2jQizMyLSfycjDmbBijWK1kpemJ3

Private Key:     edsk32vZZSKSLWDCUFKSbLYvv9GNAS3ErBftYfFgG1RiDbve5MoN5P
Public Key:      edpkuv8KcJf1aG6vsJa1XuXsqto39tHNd8YB6qfZQ6FUX6ikQoh5Dq
Public Key Hash: tz1LaPcNukJrEEJoNp2UqnhGfcqQtDPtSQ5o

Sign:
Private Key:     edsk3K3EwiTVXtEnfuERrjzjp3pa6pRrvQE3VA97cModhXVhXpnsAQ
Public Key:      edpkvVV6zH5xxewkxPN98SUTspBjYmDYZPX6PGSSDjCK5iDoT8vDQV
Public Key Hash: tz1cJaw1s1o6o2hMv9r9Q8HWwJLAnD9wqg26
*/

func TestAuthenticatedRequestInMemoryVault(t *testing.T) {
	type testCase struct {
		name       string
		signature  string
		statusCode int
	}

	cases := []testCase{
		{
			name:       "Ok",
			signature:  "edsigtkjMUUeReAm22MSYW5eR5gby4RQZfjakeKV2zwDwXmF4Gxe68zMuMK8scrbESDHWbPRkebQPVrdnsUsJ46pfP4hXT8oXZZ",
			statusCode: http.StatusOK,
		},
		{
			name:       "No signature",
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "Disabled in policy",
			signature:  "edsigtbakQb6EmsjHpXvjqDTre3EmauHei6LCqhBhRp6neyBNL2F3FX3jQsM9n8KYefWnjUABBWeATEAimaLZGSoGVqHjLc6NLM",
			statusCode: http.StatusForbidden,
		},
		{
			name:       "Invalid signature",
			signature:  "spsig1SbAZ2AWQP6fXYusCW8XowTxieZw874YcuBtKYkGEEDrvyTgReLY3jKAuoBamBALRtrEsEMG5N7zxmuxfE9MDLgsMP1YJh",
			statusCode: http.StatusForbidden,
		},
	}

	pk := "edsk3K3EwiTVXtEnfuERrjzjp3pa6pRrvQE3VA97cModhXVhXpnsAQ"
	message := "\"03a11f5f176e553a11cf184bb2b15f09f55dfc5dcb2d26d79bf5dd099d074d5f5d6c0079cae4c9a1885f17d3995619bf28636c4394458b820af19172c35000904e0000712c4c4270d9e7f512115310d8ec6acfcd878bef00\""

	priv, err := tezos.ParsePrivateKey(pk, nil)
	require.NoError(t, err)

	pub, err := tezos.EncodePublicKeyHash(priv.Public())
	require.NoError(t, err)

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return memory.NewUnparsed([]*memory.UnparsedKey{{Data: pk}}, "Mock"), nil
		}),
		Policy: map[string]*signatory.Policy{
			pub: {
				AllowedOperations:   []string{"generic", "block", "endorsement"},
				AllowedKinds:        []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				AuthorizedKeyHashes: []string{"tz1KpduK2jQizMyLSfycjDmbBijWK1kpemJ3"},
			},
		},
	}

	signer, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)
	require.NoError(t, signer.Unlock(context.Background()))

	srv := server.Server{
		Signer: signer,
		Auth:   auth.Must(auth.StaticAuthorizedKeysFromString("edpkvN5hM4s88nzgxZGkNrVqtQfaiVpix356TFrAwQoVGrKseahWG6", "edpkuv8KcJf1aG6vsJa1XuXsqto39tHNd8YB6qfZQ6FUX6ikQoh5Dq")),
	}

	handler, err := srv.Handler()
	require.NoError(t, err)

	s := httptest.NewServer(handler)
	defer s.Close()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := strings.NewReader(message)
			u, _ := url.Parse(s.URL + "/keys/" + pub)
			if c.signature != "" {
				u.RawQuery = url.Values{
					"authentication": []string{c.signature},
				}.Encode()
			}

			req, err := http.NewRequest("POST", u.String(), body)
			require.NoError(t, err)

			resp, err := s.Client().Do(req)
			require.NoError(t, err)

			require.Equal(t, c.statusCode, resp.StatusCode)
		})
	}
}
