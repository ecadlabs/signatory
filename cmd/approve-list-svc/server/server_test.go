package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/cmd/approve-list-svc/server"
	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/vault"
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

func testServer(t *testing.T, addr []net.IP) error {
	// generate hook authentication key
	_, priv, err := generateKey()
	require.NoError(t, err)

	srv := server.Server{
		PrivateKey: priv,
		Addresses:  addr,
	}

	handler, err := srv.Handler()
	require.NoError(t, err)

	testSrv := httptest.NewServer(handler)
	defer testSrv.Close()

	hookAuth, err := auth.StaticAuthorizedKeys(priv.Public())
	require.NoError(t, err)

	_, signPriv, err := generateKey()
	require.NoError(t, err)
	signPub := signPriv.Public()

	signKeyHash := signPub.Hash()
	require.NoError(t, err)

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node, g config.GlobalContext) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{
				{
					PrivateKey: signPriv,
				},
			}, "Mock")
		}),
		Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{
			{
				Key: signKeyHash,
				Val: nil,
			},
		}),
		PolicyHook: &signatory.PolicyHook{
			Address: testSrv.URL,
			Auth:    hookAuth,
		},
	}

	s, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)

	msg, _ := hex.DecodeString("11ed9d217c0000518e0118425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209630000000061947af504805682ea5d089837764b3efcc90b91db24294ff9ddb66019f332ccba17cc4741000000210000000102000000040000518e0000000000000004ffffffff0000000400000000eb1320a71e8bf8b0162a3ec315461e9153a38b70d00d5dde2df85eb92748f8d068d776e356683a9e23c186ccfb72ddc6c9857bb1704487972922e7c89a7121f800000000a8e1dd3c000000000000")
	_, err = s.Sign(context.Background(), &signatory.SignRequest{PublicKeyHash: signKeyHash, Message: msg, Source: net.IPv6loopback})
	return err
}

func TestServer(t *testing.T) {
	t.Run("Ok", func(t *testing.T) {
		require.NoError(t, testServer(t, []net.IP{net.IPv6loopback}))
	})
	t.Run("Deny", func(t *testing.T) {
		require.EqualError(t, testServer(t, nil), "policy hook: address ::1 is not allowed")
	})
}
