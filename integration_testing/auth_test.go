package integrationtesting

import (
	"context"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/integration_testing/tezbox"
	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/signatory/watermark"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAuthorization(t *testing.T) {
	priv, err := genEd25519Keys(2)
	require.NoError(t, err)
	signKey, authKey := priv[0], priv[1]

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mem": {Driver: "mem"}},
		Watermark: watermark.Ignore{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{
				{PrivateKey: signKey},
			}, "")
		}),
		Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{
			{
				Key: signKey.Public().Hash(),
				Val: &signatory.PublicKeyPolicy{
					AllowedRequests:     []string{"generic"},
					AllowedOps:          opKinds(),
					AuthorizedKeyHashes: []crypt.PublicKeyHash{authKey.Public().Hash()},
					LogPayloads:         true,
				},
			},
		}),
	}
	signer, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)

	srv := &server.Server{
		Signer:  signer,
		Address: ":0", // choose random
		Auth:    auth.StaticAuthorizedKeys(authKey.Public()),
	}

	httpServer, err := srv.New()
	require.NoError(t, err)
	l, err := startHTTPServer(httpServer)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, httpServer.Shutdown(context.Background()))
	})

	tezboxConfig, err := genBaseConfig()
	require.NoError(t, err)
	tezboxConfig.Accounts.Regular[tz1Alias] = newRemoteSignerConfig(signKey.Public(), l.Addr(), regularBalance)

	// plain `octez-client import` messes up the TexBox state for some reason --eugene
	tezboxConfig.Accounts.Regular["auth"] = &tezbox.AccountConfig{
		PublicKey:  authKey.Public().ToProtocol(),
		PrivateKey: "unencrypted:" + authKey.String(),
		Balance:    regularBalance,
	}

	cont, err := tezbox.Start(tezboxConfig)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, cont.Stop())
	})

	err = cont.ExecLog("octez-client", "transfer", "1", "from", tz1Alias, "to", "alice", "--burn-cap", "0.06425")
	require.NoError(t, err)
}
